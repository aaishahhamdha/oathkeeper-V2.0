// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/aaishahhamdha/oathkeeper/pipeline/session_store"
	"github.com/aaishahhamdha/oathkeeper/x"
)

var _ Handler = new(ErrorRedirect)

const (
	xForwardedProto = "X-Forwarded-Proto"
	xForwardedHost  = "X-Forwarded-Host"
	xForwardedUri   = "X-Forwarded-Uri"
)

type (
	ErrorRedirectConfig struct {
		To                 string `json:"to"`
		Code               int    `json:"code"`
		ReturnToQueryParam string `json:"return_to_query_param"`
	}
	ErrorRedirect struct {
		c configuration.Provider
		d ErrorRedirectDependencies
	}
	ErrorRedirectDependencies interface {
		x.RegistryWriter
	}
)

func NewErrorRedirect(
	c configuration.Provider,
	d ErrorRedirectDependencies,
) *ErrorRedirect {
	return &ErrorRedirect{c: c, d: d}
}

// ContextKeySession is the key used to store the authentication session in the request context
var ContextKeySession = struct{}{}

func (a *ErrorRedirect) Handle(w http.ResponseWriter, r *http.Request, config json.RawMessage, rule pipeline.Rule, err error) error {
	c, err := a.Config(config)
	if err != nil {
		return err
	}

	r.URL.Scheme = x.OrDefaultString(r.Header.Get(xForwardedProto), r.URL.Scheme)
	r.URL.Host = x.OrDefaultString(r.Header.Get(xForwardedHost), r.URL.Host)
	r.URL.Path = x.OrDefaultString(r.Header.Get(xForwardedUri), r.URL.Path)

	// Generate a random state for CSRF protection
	state, err := GenerateRandomState(32)
	if err != nil {
		return err
	}

	// Store the state in the session store with client info
	session_store.GlobalStore.AddStateEntry(state, r.RemoteAddr, r.UserAgent())

	// Add state to the redirect URL
	redirectURL := a.RedirectURL(r.URL, c) + "&state=" + state

	// Perform the redirect
	http.Redirect(w, r, redirectURL, c.Code)
	fmt.Printf("Redirecting to: %s with state: %s\n", redirectURL, state)

	return nil
}

func (a *ErrorRedirect) Validate(config json.RawMessage) error {
	if !a.c.ErrorHandlerIsEnabled(a.GetID()) {
		return NewErrErrorHandlerNotEnabled(a)
	}
	_, err := a.Config(config)
	return err
}

func (a *ErrorRedirect) Config(config json.RawMessage) (*ErrorRedirectConfig, error) {
	var c ErrorRedirectConfig
	if err := a.c.ErrorHandlerConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrErrorHandlerMisconfigured(a, err)
	}

	if c.Code < 301 || c.Code > 302 {
		c.Code = http.StatusFound
	}

	return &c, nil
}

func (a *ErrorRedirect) GetID() string {
	return "redirect"
}

func (a *ErrorRedirect) RedirectURL(uri *url.URL, c *ErrorRedirectConfig) string {
	if c.ReturnToQueryParam == "" {
		return c.To
	}

	u, err := url.Parse(c.To)
	if err != nil {
		return c.To
	}

	q := u.Query()
	q.Set(c.ReturnToQueryParam, uri.String())
	u.RawQuery = q.Encode()
	return u.String()
}

// GenerateRandomState creates a cryptographically secure random state string
func GenerateRandomState(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
