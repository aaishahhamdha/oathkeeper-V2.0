// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"

	"github.com/aaishahhamdha/oathkeeper/pipeline/authn"
	"github.com/aaishahhamdha/oathkeeper/x"

	"github.com/aaishahhamdha/oathkeeper/proxy"
	"github.com/aaishahhamdha/oathkeeper/rule"
)

const (
	DecisionPath = "/decisions"

	xForwardedMethod = "X-Forwarded-Method"
	xForwardedProto  = "X-Forwarded-Proto"
	xForwardedHost   = "X-Forwarded-Host"
	xForwardedUri    = "X-Forwarded-Uri"
)

type decisionHandlerRegistry interface {
	x.RegistryWriter
	x.RegistryLogger

	RuleMatcher() rule.Matcher
	ProxyRequestHandler() proxy.RequestHandler
}

type DecisionHandler struct {
	r decisionHandlerRegistry
}

func NewJudgeHandler(r decisionHandlerRegistry) *DecisionHandler {
	return &DecisionHandler{r: r}
}

func (h *DecisionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if len(r.URL.Path) >= len(DecisionPath) && r.URL.Path[:len(DecisionPath)] == DecisionPath {
		r.Method = x.OrDefaultString(r.Header.Get(xForwardedMethod), r.Method)
		r.URL.Scheme = x.OrDefaultString(r.Header.Get(xForwardedProto),
			x.IfThenElseString(r.TLS != nil, "https", "http"))
		r.URL.Host = x.OrDefaultString(r.Header.Get(xForwardedHost), r.Host)
		r.URL.Path = x.OrDefaultString(strings.SplitN(r.Header.Get(xForwardedUri), "?", 2)[0], r.URL.Path[len(DecisionPath):])

		h.decisions(w, r)
	} else {
		next(w, r)
	}
}

// swagger:route GET /decisions api decisions
//
// # Access Control Decision API
//
// > This endpoint works with all HTTP Methods (GET, POST, PUT, ...) and matches every path prefixed with /decisions.
//
// This endpoint mirrors the proxy capability of ORY Oathkeeper's proxy functionality but instead of forwarding the
// request to the upstream server, returns 200 (request should be allowed), 401 (unauthorized), or 403 (forbidden)
// status codes. This endpoint can be used to integrate with other API Proxies like Ambassador, Kong, Envoy, and many more.
//
//	Schemes: http, https
//
//	Responses:
//	  200: emptyResponse
//	  401: genericError
//	  403: genericError
//	  404: genericError
//	  500: genericError
func (h *DecisionHandler) decisions(w http.ResponseWriter, r *http.Request) {
	h.r.Logger().Debug("decisions function called")
	fields := map[string]interface{}{
		"http_method":     r.Method,
		"http_url":        r.URL.String(),
		"http_host":       r.Host,
		"http_user_agent": r.UserAgent(),
	}

	if sess, ok := r.Context().Value(proxy.ContextKeySession).(*authn.AuthenticationSession); ok {
		fields["subject"] = sess.Subject
	}

	rl, err := h.r.RuleMatcher().Match(r.Context(), r.Method, r.URL, rule.ProtocolHTTP)
	if err != nil {
		h.r.Logger().WithError(err).
			WithFields(fields).
			WithField("granted", false).
			Warn("Access request denied")
		h.r.ProxyRequestHandler().HandleError(w, r, rl, err)
		return
	}

	s, err := h.r.ProxyRequestHandler().HandleRequest(r, rl)
	if err != nil {
		h.r.Logger().WithError(err).
			WithFields(fields).
			WithField("granted", false).
			Info("Access request denied")
		h.r.ProxyRequestHandler().HandleError(w, r, rl, err)
		return
	}

	h.r.Logger().
		WithFields(fields).
		WithField("granted", true).
		Info("Access request granted")

	// marked by Aaishah
	// Copy headers from the authentication session to the response
	for k := range s.Header {
		// Avoid copying the original Content-Length header from the client
		if strings.ToLower(k) == "content-length" {
			continue
		}

		w.Header().Set(k, s.Header.Get(k))
	}

	// Copy cookies from the authentication session to the response
	copyCookies(w, s.Header)
	sessionID := s.Header.Get("wso2_session_id")
	h.r.Logger().WithField("wso2_session_id", sessionID).Debug("Session ID from header in decision")
	h.r.Logger().WithField("extra_info", s.Extra).Debug("Session extra information")
	// If there's session data in Extra that needs to be sent to the client
	if s.Extra != nil {
		// Check for cookie information that needs to be set
		if cookieInfo, ok := s.Extra["set_cookie"].(map[string]interface{}); ok {
			h.r.Logger().WithField("cookie_info", cookieInfo).Debug("Setting cookie from session extra data")
			cookie := &http.Cookie{
				Name:     cookieInfo["name"].(string),
				Value:    cookieInfo["value"].(string),
				Path:     cookieInfo["path"].(string),
				HttpOnly: cookieInfo["httpOnly"].(bool),
				Secure:   cookieInfo["secure"].(bool),
			}
			if maxAge, ok := cookieInfo["maxAge"].(int); ok {
				cookie.MaxAge = maxAge
			}
			http.SetCookie(w, cookie)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// copyCookies extracts cookies from the header and sets them in the response
func copyCookies(w http.ResponseWriter, header http.Header) {
	if cookies := header.Get("Set-Cookie"); cookies != "" {
		// Multiple cookies might be separated in the header
		for _, cookieStr := range header.Values("Set-Cookie") {
			if cookieStr != "" {
				w.Header().Add("Set-Cookie", cookieStr)
			}
		}
	}
}
