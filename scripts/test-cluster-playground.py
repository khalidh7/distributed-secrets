#!/usr/bin/env python3
"""Exercise the running disposable Raft lab; restore stopped nodes on exit."""
import json
import time
import urllib.error
import urllib.request
import uuid

BASE = 'http://127.0.0.1:3000'

def request(path, method='GET', body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=12)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else None

def wait_for(predicate, description, timeout=18):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        code, state = request('/playground/cluster')
        if code == 200 and predicate(state):
            return state
        time.sleep(0.2)
    raise AssertionError('Timed out: ' + description)

def control(node, action):
    code, result = request(f'/playground/nodes/{node}/{action}', 'POST', {})
    assert code == 200, result

try:
    session = request('/playground/session')[1]
    if not session['unlocked']:
        for share in session['shares'][:3]:
            code, result = request('/playground/unlock', 'POST', {'share': share})
            assert code == 200, result
        assert result['unlocked'], result
    state = wait_for(lambda s: s['online'] == 3 and s['writable'], 'initial election')
    token = request('/playground/session')[1]['token']
    leader = state['leader']
    term = max(n['term'] for n in state['nodes'])
    path = '/v1/secrets/sandbox/raft-test-' + uuid.uuid4().hex[:8]
    before_index = max(n['commit_index'] for n in state['nodes'])
    code, result = request(path, 'PUT', {'value': 'before-failover'}, token)
    assert code == 201, result
    state = wait_for(lambda s: all(n['last_applied'] > before_index for n in s['nodes']), 'initial replication')
    committed = max(n['commit_index'] for n in state['nodes'])
    print('PASS: real write committed and replicated to all three nodes')

    control(leader, 'stop')
    state = wait_for(lambda s: s['online'] == 2 and s['writable'] and s['leader'] != leader, 'replacement leader')
    assert max(n['term'] for n in state['nodes']) > term
    assert any(e['kind'] == 'leader_elected' and e['term'] > term for n in state['nodes'] if n['online'] for e in n.get('events') or [])
    assert request(path, token=token)[1]['data']['value'] == 'before-failover'
    code, result = request(path, 'PUT', {'value': 'after-failover'}, token)
    assert code == 201 and result['version'] == 2, result
    print('PASS: dropped leader; survivors elected a new leader in a higher term; reads and writes continued')

    control(leader, 'start')
    state = wait_for(lambda s: s['online'] == 3 and all(n['last_applied'] > committed for n in s['nodes']), 'restarted node catches up')
    assert len({n['commit_index'] for n in state['nodes']}) == 1
    print('PASS: restarted old leader recovered its WAL and caught up')

    active_leader = state['leader']
    for node in state['nodes']:
        if node['id'] != active_leader:
            control(node['id'], 'stop')
    state = wait_for(lambda s: s['online'] == 1 and not s['writable'], 'loss of quorum')
    code, result = request(path, 'PUT', {'value': 'must-not-commit'}, token)
    assert code == 503, result
    assert request(path, token=token)[1]['data']['value'] == 'after-failover'
    print('PASS: majority loss blocked writes and preserved the last committed value')
finally:
    for node in ['node1', 'node2', 'node3']:
        control(node, 'start')
    wait_for(lambda s: s['online'] == 3 and s['writable'], 'restore cluster')
    print('All three nodes restored and ready.')
