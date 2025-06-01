// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"net/http"
)

type simpleResponseWriter struct {
	header    http.Header
	buffer    *bytes.Buffer
	code      int
	sessionID string
}

func NewSimpleResponseWriter(sessionID string) *simpleResponseWriter {
	return &simpleResponseWriter{
		header:    http.Header{},
		buffer:    bytes.NewBuffer([]byte{}),
		code:      http.StatusOK,
		sessionID: sessionID,
	}
}

func (r *simpleResponseWriter) Header() http.Header {
	return r.header
}

func (r *simpleResponseWriter) Write(b []byte) (int, error) {
	return r.buffer.Write(b)
}

func (r *simpleResponseWriter) WriteHeader(statusCode int) {
	r.code = statusCode
	if r.sessionID != "" {
		SessionCookie := http.Cookie{
			Name:     "wso2_session_id",
			Value:    r.sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   3600, // 1 hour in seconds
			SameSite: http.SameSiteLaxMode,
		}
		r.header.Add("Set-Cookie", SessionCookie.String())
	}
}
