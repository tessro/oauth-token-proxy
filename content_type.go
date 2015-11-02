package main

import (
	"net/http"
)

type ContentTypeVerifier struct {
	ContentType string
	Next        http.Handler
}

// Reject requests that provide a body with an unexpected Content-Type.
//
// Assumes clients always specify Content-Type when providing an entity-body.
// A stricter approach might reject requests that provide a body and no
// Content-Type header.
func (h *ContentTypeVerifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cts := req.Header["Content-Type"]
	for _, ct := range cts {
		if ct != h.ContentType {
			h.Fail(rw, req)
			return
		}
	}

	h.Next.ServeHTTP(rw, req)
}

func (h *ContentTypeVerifier) Fail(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(400)
	rw.Write([]byte(`{"error":"Invalid content type. Did you forget to set a valid Content-Type header?"}`))
	rw.Write([]byte("\n"))
}
