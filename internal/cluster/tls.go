package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

func LoadMTLS(certFile, keyFile, caFile string, allowedPeers map[string]bool) (*tls.Config, *httpClientTLS, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("cluster CA contains no certificates")
	}
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	if len(allowedPeers) > 0 {
		server.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("missing node certificate")
			}
			cert := state.PeerCertificates[0]
			for _, dns := range cert.DNSNames {
				if allowedPeers[dns] {
					return nil
				}
			}
			if allowedPeers[cert.Subject.CommonName] {
				return nil
			}
			return errors.New("certificate identity is not a cluster member")
		}
	}
	client := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool}
	return server, &httpClientTLS{Config: client}, nil
}

// A private wrapper keeps cluster TLS construction independent from net/http.
type httpClientTLS struct{ Config *tls.Config }
