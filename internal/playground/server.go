// Package playground serves the local UI and proxies requests over verified TLS.
package playground

import (
	"embed"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

//go:embed web/*
var assets embed.FS

func Handler(upstream *url.URL, transport http.RoundTripper, labs ...*Lab) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = transport
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"Cannot reach the secrets service. Check that it is running and its CA certificate is valid."}`))
	}
	files, _ := fs.Sub(assets, "web")
	mux := http.NewServeMux()
	if len(labs) > 0 && labs[0] != nil {
		labs[0].Register(mux, transport)
	} else {
		mux.Handle("/v1/", proxy)
		mux.HandleFunc("GET /playground/session", func(w http.ResponseWriter, r *http.Request) { labJSON(w, 200, map[string]string{"mode": "single"}) })
	}
	mux.Handle("/", http.FileServer(http.FS(files)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			http.Error(w, "Local access only", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Cross-site requests are not allowed", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			http.Error(w, "Cross-origin requests are not allowed", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
