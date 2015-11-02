package main

import (
	"strings"

	"net/http"
	"net/http/httputil"
	"net/url"
)

type Upstream struct {
	prefix  string
	url     *url.URL
	handler *httputil.ReverseProxy
}

func (u *Upstream) Matches(path string) bool {
	return strings.HasPrefix(path, u.prefix)
}

func (u *Upstream) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	path := req.URL.Path[len(u.prefix):]
	req.URL.Scheme = u.url.Scheme
	req.URL.Host = u.url.Host
	req.URL.Path = u.url.Path + path
	u.handler.ServeHTTP(rw, req)
}
