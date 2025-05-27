// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/aaishahhamdha/oathkeeper/x/header"
	"github.com/ory/x/otelx"
	"github.com/ory/x/stringsx"

	"github.com/ory/herodot"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
)

func init() {
	gjson.AddModifier("this", func(json, arg string) string {
		return json
	})
}

type AuthenticatorCookieSessionFilter struct {
}

type AuthenticatorCookieSessionConfiguration struct {
	Only               []string          `json:"only"`
	CheckSessionURL    string            `json:"check_session_url"`
	PreserveQuery      bool              `json:"preserve_query"`
	PreservePath       bool              `json:"preserve_path"`
	ExtraFrom          string            `json:"extra_from"`
	SubjectFrom        string            `json:"subject_from"`
	PreserveHost       bool              `json:"preserve_host"`
	ForwardHTTPHeaders []string          `json:"forward_http_headers"`
	SetHeaders         map[string]string `json:"additional_headers"`
	ForceMethod        string            `json:"force_method"`
}

func (a *AuthenticatorCookieSessionConfiguration) GetCheckSessionURL() string {
	return a.CheckSessionURL
}

func (a *AuthenticatorCookieSessionConfiguration) GetPreserveQuery() bool {
	return a.PreserveQuery
}

func (a *AuthenticatorCookieSessionConfiguration) GetPreservePath() bool {
	return a.PreservePath
}

func (a *AuthenticatorCookieSessionConfiguration) GetPreserveHost() bool {
	return a.PreserveHost
}

func (a *AuthenticatorCookieSessionConfiguration) GetForwardHTTPHeaders() []string {
	return a.ForwardHTTPHeaders
}

func (a *AuthenticatorCookieSessionConfiguration) GetSetHeaders() map[string]string {
	return a.SetHeaders
}

func (a *AuthenticatorCookieSessionConfiguration) GetForceMethod() string {
	return a.ForceMethod
}

type AuthenticatorCookieSession struct {
	c      configuration.Provider
	client *http.Client
	tracer trace.Tracer
}

var _ AuthenticatorForwardConfig = new(AuthenticatorCookieSessionConfiguration)

func NewAuthenticatorCookieSession(c configuration.Provider, provider trace.TracerProvider) *AuthenticatorCookieSession {
	return &AuthenticatorCookieSession{
		c: c,
		client: &http.Client{
			Transport: otelhttp.NewTransport(
				http.DefaultTransport,
				otelhttp.WithTracerProvider(provider),
			),
		},
		tracer: provider.Tracer("oauthkeeper/pipeline/authn"),
	}
}

func (a *AuthenticatorCookieSession) GetID() string {
	return "cookie_session"
}

func (a *AuthenticatorCookieSession) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorCookieSession) Config(config json.RawMessage) (*AuthenticatorCookieSessionConfiguration, error) {
	var c AuthenticatorCookieSessionConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	if len(c.ExtraFrom) == 0 {
		c.ExtraFrom = "extra"
	}

	if len(c.SubjectFrom) == 0 {
		c.SubjectFrom = "subject"
	}

	// Add Authorization and Cookie headers for backward compatibility
	c.ForwardHTTPHeaders = append(c.ForwardHTTPHeaders, []string{header.Cookie}...)

	return &c, nil
}

func (a *AuthenticatorCookieSession) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) (err error) {
	ctx, span := a.tracer.Start(r.Context(), "pipeline.authn.AuthenticatorCookieSession.Authenticate")
	defer otelx.End(span, &err)
	r = r.WithContext(ctx)
	fmt.Println("AuthenticatorCookieSession.Authenticate called")

	cf, err := a.Config(config)
	if err != nil {
		fmt.Println("Error getting config: ", err)
		return err
	}

	if !cookieSessionResponsible(r, cf.Only) {
		fmt.Println("Authenticator not responsible for request")
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	body, err := forwardRequestToSessionStore(a.client, r, cf)
	if err != nil {
		fmt.Println("Error forwarding request: ", err)
		return err
	}

	var (
		subject string
		extra   map[string]interface{}

		subjectRaw = []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.SubjectFrom).Raw, "null"))
		extraRaw   = []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.ExtraFrom).Raw, "null"))
	)

	if err = json.Unmarshal(subjectRaw, &subject); err != nil {
		return helper.ErrForbidden.WithReasonf("The configured subject_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.SubjectFrom, body, subjectRaw).WithTrace(err)
	}

	if err = json.Unmarshal(extraRaw, &extra); err != nil {
		return helper.ErrForbidden.WithReasonf("The configured extra_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.ExtraFrom, body, extraRaw).WithTrace(err)
	}

	session.Subject = subject
	session.Extra = extra
	return nil
}

func cookieSessionResponsible(r *http.Request, only []string) bool {
	// Debug: Log all cookies received
	fmt.Printf("Received cookies: %v\n", r.Cookies())
	fmt.Printf("Checking against only list: %v\n", only)

	if len(only) == 0 {
		return len(r.Cookies()) > 0
	}

	for _, cookieName := range only {
		if _, err := r.Cookie(cookieName); err == nil {
			fmt.Printf("Found matching cookie: %s\n", cookieName)
			return true
		}
	}

	fmt.Println("No matching cookies found")
	return false
}

func forwardRequestToSessionStore(client *http.Client, r *http.Request, cf AuthenticatorForwardConfig) (json.RawMessage, error) {
	req, err := PrepareRequest(r, cf)
	if err != nil {
		fmt.Println("Error preparing request: ", err)
		return nil, err
	}

	res, err := client.Do(req.WithContext(r.Context()))
	fmt.Println("Request URL: ", req.URL.String())
	fmt.Println("Response from check session: ", res)

	if err != nil {
		fmt.Println("Error: ", err)
		return nil, helper.ErrForbidden.WithReason(err.Error()).WithTrace(err)
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Println("Error reading response body: ", err)
			return json.RawMessage{}, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch cookie session context from remote: %+v", err))
		}
		return body, nil
	} else {
		return json.RawMessage{}, errors.WithStack(helper.ErrUnauthorized)
	}
}

func PrepareRequest(r *http.Request, cf AuthenticatorForwardConfig) (http.Request, error) {
	reqURL, err := url.Parse(cf.GetCheckSessionURL())
	fmt.Println("Parsed checksession URL: ", reqURL)
	if err != nil {
		return http.Request{}, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to parse session check URL: %s", err))
	}

	if !cf.GetPreserveQuery() {
		reqURL.RawQuery = r.URL.RawQuery
	}

	m := cf.GetForceMethod()
	if m == "" {
		m = r.Method
	}

	req := http.Request{
		Method: m,
		URL:    reqURL,
		Header: http.Header{},
	}
	fmt.Println("Request method: ", req.Method)
	fmt.Println("Request URL: ", req.URL.String())
	fmt.Println("Request headers: ", r.Header)
	fmt.Println("Request preserve path: ", cf.GetPreservePath())
	fmt.Println("Request preserve query: ", cf.GetPreserveQuery())
	fmt.Println("Request preserve host: ", cf.GetPreserveHost())
	fmt.Println("Request force method: ", cf.GetForceMethod())

	// We need to copy only essential and configurable headers
	for requested, v := range r.Header {
		for _, allowed := range cf.GetForwardHTTPHeaders() {
			// Check against canonical names of header
			if requested == header.Canonical(allowed) {
				req.Header[requested] = v
			}
		}
	}

	for k, v := range cf.GetSetHeaders() {
		req.Header.Set(k, v)
	}

	if cf.GetPreserveHost() {
		req.Header.Set(header.XForwardedHost, r.Host)
	}
	return req, nil
}
