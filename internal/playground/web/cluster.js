'use strict';
(() => {
  const ids = ['node1', 'node2', 'node3'];
  let snapshot = null, polling = false, actionBusy = false, stopped = false;
  let events = [], seen = new Set(), lastHeartbeat = {}, previous = {}, failures = 0;
  let selectedShares = new Set();
  const text = (id, value) => { document.getElementById(id).textContent = value; };
  const names = { election_started:'Election timeout → candidate; self-vote recorded', leader_elected:'Majority votes received → elected leader', vote_granted:'Granted vote', stepped_down:'Stepped down → follower', log_appended:'Encrypted entry persisted to leader WAL', replication_ack:'Follower acknowledged persisted entry', quorum_commit:'Majority persisted → commit index advanced', entry_received:'Received and persisted encrypted entry', commit_applied:'Leader commit received → apply entry' };
  function eventLine(event, key) {
    if (seen.has(key)) return;
    seen.add(key); events.push(event);
  }
  function renderWAL(node) {
    const container = document.getElementById('wal-entries');
    const signature = JSON.stringify([node?.log,node?.commit_index,node?.online]);
    if (container.dataset.signature === signature) return;
    container.dataset.signature = signature;
    container.replaceChildren();
    const entries = (node?.log || []).filter(entry => !entry.snapshot);
    if (!entries.length) {
      const empty=document.createElement('p');empty.textContent=node?.online?'No uncompacted WAL entries. The snapshot marker below is the recovery boundary.':'node1 is offline. Its WAL remains on disk.';container.append(empty);
      text('wal-state',node?.online?'READY':'NODE OFFLINE · FILE PRESERVED');return;
    }
    for (const entry of entries) {
      const row=document.createElement('div');row.className=`wal-record ${entry.index<=node.last_applied?'committed':'pending'}`;
      const index=document.createElement('span');index.textContent=String(entry.index).padStart(4,'0');
      const operation=document.createElement('strong');operation.textContent='replicated command';
      const meta=document.createElement('code');meta.textContent=`index=${entry.index}  term=${entry.term}  payload=redacted`;
      const state=document.createElement('em');state.textContent=entry.index<=node.last_applied?'COMMITTED':'PERSISTED';
      row.append(index,operation,meta,state);container.append(row);
    }
    text('wal-state',`${entries.length} RECORD${entries.length===1?'':'S'} · ${node.online?'FILE OPEN':'FILE PRESERVED'}`);
  }
  function renderEvents() {
    events.sort((a,b) => new Date(b.at) - new Date(a.at)); events = events.slice(0,80);
    // Keep deduplication bounded; event IDs are monotonic within a process generation.
    if (seen.size > 12000) seen = new Set([...seen].slice(-6000));
    const list = document.getElementById('raft-events'); list.replaceChildren();
    for (const event of events.slice(0,35)) {
      const li = document.createElement('li'); li.className = `event-${event.kind}`;
      const time = document.createElement('time'); time.textContent = new Date(event.at).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, fractionalSecondDigits:1 });
      const content = document.createElement('div'); const strong = document.createElement('strong'); strong.textContent = `${event.node} ${event.peer ? `→ ${event.peer}` : ''}`;
      const detail = document.createElement('span'); detail.textContent = names[event.kind] || event.kind;
      const meta = document.createElement('small'); meta.textContent = `term ${event.term || 0}${event.index ? ` · index ${event.index}` : ''}`;
      content.append(strong,detail); li.append(time, content, meta); list.append(li);
    }
    if (!events.length) {const li=document.createElement('li');li.className='empty-event';li.textContent='No new events. Heartbeats continue between elections and writes.';list.append(li);}
  }
  function drawNodes() {
    const container = document.getElementById('node-cards');
    for (const id of ids) {
      const card = document.createElement('article'); card.id=`card-${id}`; card.className='raft-node offline';
      card.innerHTML=`<div class="node-card-top"><span class="node-symbol">▤</span><span class="node-role" id="role-${id}">STARTING</span></div><h3>${id}</h3><div class="node-address">127.0.0.1:${8440+ids.indexOf(id)+1}</div><dl><div><dt>Term</dt><dd id="term-${id}">—</dd></div><div><dt>Voted for</dt><dd id="vote-${id}">—</dd></div><div><dt>Commit / applied</dt><dd id="commit-${id}">0 / 0</dd></div></dl><div class="election-clock"><progress id="clock-${id}" max="2800" value="0" aria-label="${id} election timeout remaining"></progress><small id="clock-label-${id}">Waiting…</small></div><button id="toggle-${id}" type="button" class="node-toggle" aria-label="Stop ${id}">↓ Stop node</button>`;
      container.append(card);
      document.getElementById(`toggle-${id}`).addEventListener('click', () => {
        const node=snapshot?.nodes.find(n=>n.id===id); if (node) control(id,node.running?'stop':'start');
      });
      const row=document.createElement('div');row.className='log-row';row.id=`log-row-${id}`;
      const label=document.createElement('strong');label.textContent=id;
      const cells=document.createElement('div');cells.className='log-cells';cells.id=`log-${id}`;
      row.append(label,cells);document.getElementById('log-rows').append(row);
    }
  }
  function render(next) {
    snapshot=next;failures=0;
    document.getElementById('connection').className='connection online';text('connection',next.unlocked?'Live Raft cluster':'Cluster sealed · operator login required');
    text('cluster-live','● LIVE · 200 MS');
    text('cluster-leader',next.leader||'Electing…');
    const online=next.nodes.filter(n=>n.online),term=Math.max(0,...online.map(n=>n.term));
    text('cluster-term',term);text('cluster-quorum',`${next.online} / 3`);
    text('cluster-commit',Math.max(0,...online.map(n=>n.commit_index)));
    const banner=document.getElementById('cluster-banner');banner.className=!next.unlocked?'sealed':next.writable?'healthy':next.online<2?'unavailable':'electing';
    banner.textContent=!next.unlocked?`Sealed · ${next.unlock_progress} of ${next.unlock_threshold} recovery shares accepted`:next.writable?`Quorum available · ${next.leader} coordinates writes · ${next.online===3?'all nodes online':'one node can be offline and writes still commit'}`:next.online<2?'Quorum lost · writes blocked · restart nodes to reach 2 of 3':'Election in progress · waiting for a majority vote';
    document.getElementById('drop-leader').disabled=actionBusy||!next.leader||!next.unlocked;
    document.getElementById('restore-cluster').disabled=actionBusy||next.nodes.every(n=>n.running);
    let changedEvents=false;
    for (const node of next.nodes) {
      const role=node.online?node.role:node.running?'starting':'offline';
      const card=document.getElementById(`card-${node.id}`);card.className=`raft-node ${role}`;
      text(`role-${node.id}`,role.toUpperCase());text(`term-${node.id}`,node.term??'—');text(`vote-${node.id}`,node.voted_for||'—');
      text(`commit-${node.id}`,`${node.commit_index||0} / ${node.last_applied||0}`);
      const clock=document.getElementById(`clock-${node.id}`);clock.value=node.online&&node.role!=='leader'?node.election_remaining_ms:0;
      text(`clock-label-${node.id}`,!node.online?(node.running?'Starting / reconnecting':'Process stopped · disk preserved'):node.role==='leader'?'Sending heartbeats · 300 ms':`Election timeout: ${(node.election_remaining_ms/1000).toFixed(1)} s`);
      const toggle=document.getElementById(`toggle-${node.id}`);toggle.textContent=node.running?'↓ Stop node':'↻ Restart node';toggle.setAttribute('aria-label',`${node.running?'Stop':'Restart'} ${node.id}`);toggle.disabled=actionBusy;
      const wire=document.getElementById(`wire-${node.id}`);wire.setAttribute('class',node.online?role:'offline');
      if (node.online&&node.last_heartbeat&&!node.last_heartbeat.startsWith('0001')&&lastHeartbeat[node.id]!==node.last_heartbeat) {
        wire.classList.remove('pulse');void wire.getBoundingClientRect();wire.classList.add('pulse');
        lastHeartbeat[node.id]=node.last_heartbeat;
      }
      const log=document.getElementById(`log-${node.id}`); const signature=JSON.stringify([node.log,node.commit_index,node.last_applied,node.online]);
      if(log.dataset.signature!==signature){
        log.dataset.signature=signature;log.replaceChildren();
        for(const entry of node.log||[]){const cell=document.createElement('span');cell.className=entry.index<=node.last_applied?'log-entry committed':'log-entry pending';cell.textContent=`${entry.snapshot?'S':''}${entry.index} / ${entry.term}`;cell.title=`${entry.snapshot?'Snapshot boundary. ':''}Index ${entry.index}, term ${entry.term}. ${entry.index<=node.last_applied?'Committed and applied':'Persisted; not yet applied'}`;log.append(cell);}
        if(!node.log?.length){const empty=document.createElement('span');empty.className='empty-log';empty.textContent='No log entries yet';log.append(empty);}
      }
      document.getElementById(`log-row-${node.id}`).classList.toggle('offline',!node.online);
      const old=previous[node.id];
      if(old&&old.running&&!node.running){eventLine({node:node.id,kind:'Process stopped · missed heartbeats trigger an election',at:new Date().toISOString(),term:old.term},`${node.id}:stopped:${node.generation}`);changedEvents=true;}
      if(old&&!old.running&&node.running){eventLine({node:node.id,kind:'Process restarted · recovering persistent Raft state',at:new Date().toISOString(),term:node.term},`${node.id}:started:${node.generation}`);changedEvents=true;}
      for(const event of node.events||[]){const key=`${node.id}:${node.generation}:${event.id}`;if(!seen.has(key)){eventLine(event,key);changedEvents=true;}}
      previous[node.id]=node;
    }
    renderWAL(next.nodes.find(node=>node.id==='node1'));
    if(changedEvents)renderEvents();
  }
  async function poll() {
    if(polling||stopped)return;polling=true;
    try{const response=await fetch('/playground/cluster',{cache:'no-store',signal:AbortSignal.timeout(2000)});if(!response.ok)throw new Error('Cluster status unavailable');render(await response.json());}
    catch(error){failures++;text('cluster-live','DISCONNECTED');text('connection','Cluster supervisor unavailable');document.getElementById('connection').className='connection offline';text('cluster-banner','Live telemetry disconnected. Displayed node values may be stale.');document.getElementById('cluster-banner').className='unavailable';document.getElementById('drop-leader').disabled=true;}
    finally{polling=false;if(!stopped)setTimeout(poll,200);}
  }
  async function control(id,action) {
    if(actionBusy)return;actionBusy=true;if(snapshot)render(snapshot);
    text('fault-message',`${action==='stop'?'Stopping':'Restarting'} ${id}…`);
    try{
      const response=await fetch(`/playground/nodes/${id}/${action}`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});
      const result=await response.json();if(!response.ok)throw new Error(result.error||'Node action failed');
      text('fault-message',action==='stop'?`${id} stopped.`:`${id} started. Recovering persisted state.`);
    }catch(error){text('fault-message',error.message);}
    finally{actionBusy=false;}
  }
  function buildShareCards(shares) {
    const container=document.getElementById('share-cards');container.replaceChildren();
    shares.forEach((share,index)=>{
      const button=document.createElement('button');button.type='button';button.className='share-card';button.dataset.share=share;
      const number=document.createElement('span');number.textContent=String(index+1).padStart(2,'0');
      const copy=document.createElement('div');const strong=document.createElement('strong');strong.textContent=`Recovery share ${index+1}`;
      const code=document.createElement('code');code.textContent=`${share.slice(0,8)}••••${share.slice(-8)}`;
      const status=document.createElement('i');status.textContent='SELECT';copy.append(strong,code);button.append(number,copy,status);
      button.addEventListener('click',()=>{
        if(button.classList.contains('submitted'))return;
        if(selectedShares.has(share)){selectedShares.delete(share);button.classList.remove('selected');status.textContent='SELECT';}
        else if(selectedShares.size<3){selectedShares.add(share);button.classList.add('selected');status.textContent='READY';}
        document.querySelectorAll('.share-card:not(.selected)').forEach(card=>card.classList.toggle('locked',selectedShares.size===3));
        text('unlock-count',`${selectedShares.size} / 3`);document.getElementById('unlock-cluster').disabled=selectedShares.size!==3;
        text('unlock-message',selectedShares.size===3?'Threshold reached. Submit to reconstruct the root key.':`Select ${3-selectedShares.size} more distinct share${3-selectedShares.size===1?'':'s'}.`);
      });container.append(button);
    });
  }
  async function unlockCluster() {
    const button=document.getElementById('unlock-cluster');button.disabled=true;actionBusy=true;
    let progress=0;
    try{
      for(const share of selectedShares){
        text('unlock-message',`Submitting share ${progress+1} to all three sealed nodes…`);
        const response=await fetch('/playground/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({share}),signal:AbortSignal.timeout(10000)});
        const result=await response.json();if(!response.ok)throw new Error(result.error||'Unlock failed');
        progress=result.progress;const card=document.querySelector(`.share-card[data-share="${CSS.escape(share)}"]`);card.classList.add('submitted');card.querySelector('i').textContent='ACCEPTED';
        text('unlock-count',`${progress} / 3`);document.getElementById('unlock-progress-bar').style.width=`${progress/3*100}%`;
        await new Promise(resolve=>setTimeout(resolve,450));
        if(result.unlocked){document.getElementById('token').value=result.token;}
      }
      text('unlock-message','Root reconstructed in memory. KEK unwrapped. Starting Raft…');
      document.getElementById('shamir-gate').classList.add('unlocked');
      setTimeout(()=>{document.getElementById('shamir-gate').hidden=true;document.body.classList.remove('login-active');text('form-message','Vault unlocked.');},700);
    }catch(error){text('unlock-message',error.message);button.disabled=false;}
    finally{actionBusy=false;}
  }
  window.addEventListener('cluster-ready',(event)=>{
    document.body.classList.add('cluster-mode');
    document.getElementById('cluster-panel').hidden=false;document.getElementById('fault-controls').hidden=false;
    document.querySelector('.visual-panel').hidden=true;document.getElementById('vault-tools').hidden=true;
    document.querySelector('.transport-note').textContent='↳ Auto-routed to the leader · TLS + mTLS between nodes';
    buildShareCards(event.detail.shares || []);
    if(event.detail.unlocked){document.getElementById('shamir-gate').hidden=true;text('form-message','');}
    else{document.getElementById('shamir-gate').hidden=false;document.body.classList.add('login-active');text('form-message','Unlock the vault to continue.');}
    drawNodes();poll();
    document.getElementById('drop-leader').addEventListener('click',()=>{if(snapshot?.leader)control(snapshot.leader,'stop');});
    document.getElementById('restore-cluster').addEventListener('click',async()=>{for(const node of snapshot?.nodes||[])if(!node.running)await control(node.id,'start');});
    document.getElementById('clear-events').addEventListener('click',()=>{events=[];renderEvents();});
    document.getElementById('unlock-cluster').addEventListener('click',unlockCluster);
    document.getElementById('restart-cluster').addEventListener('click',async()=>{if(actionBusy)return;actionBusy=true;text('fault-message','Restarting cluster…');try{const response=await fetch('/playground/demo/restart',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(15000)});if(!response.ok)throw new Error('Could not restart cluster');location.reload();}catch(error){text('fault-message',error.message);actionBusy=false;}});
  });
  window.addEventListener('pagehide',()=>{stopped=true;});
})();
