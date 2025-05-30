// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/aaishahhamdha/oathkeeper/x/header"
	"github.com/ory/herodot"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/stringsx"
)

func init() {
	gjson.AddModifier("this", func(json, arg string) string {
		return json
	})
}

type AuthenticatorBearerTokenFilter struct {
}

type AuthenticatorBearerTokenConfiguration struct {
	CheckSessionURL     string                      `json:"check_session_url"`
	BearerTokenLocation *helper.BearerTokenLocation `json:"token_from"`
	Prefix              string                      `json:"prefix"`
	PreserveQuery       bool                        `json:"preserve_query"`
	PreservePath        bool                        `json:"preserve_path"`
	PreserveHost        bool                        `json:"preserve_host"`
	ExtraFrom           string                      `json:"extra_from"`
	SubjectFrom         string                      `json:"subject_from"`
	ForwardHTTPHeaders  []string                    `json:"forward_http_headers"`
	SetHeaders          map[string]string           `json:"additional_headers"`
	ForceMethod         string                      `json:"force_method"`
}

func (a *AuthenticatorBearerTokenConfiguration) GetCheckSessionURL() string {
	return a.CheckSessionURL
}

func (a *AuthenticatorBearerTokenConfiguration) GetPreserveQuery() bool {
	return a.PreserveQuery
}

func (a *AuthenticatorBearerTokenConfiguration) GetPreservePath() bool {
	return a.PreservePath
}

func (a *AuthenticatorBearerTokenConfiguration) GetPreserveHost() bool {
	return a.PreserveHost
}

func (a *AuthenticatorBearerTokenConfiguration) GetForwardHTTPHeaders() []string {
	return a.ForwardHTTPHeaders
}

func (a *AuthenticatorBearerTokenConfiguration) GetSetHeaders() map[string]string {
	return a.SetHeaders
}

func (a *AuthenticatorBearerTokenConfiguration) GetForceMethod() string {
	return a.ForceMethod
}

type AuthenticatorBearerToken struct {
	c      configuration.Provider
	client *http.Client
	tracer trace.Tracer
	logger *logrusx.Logger
}

var _ AuthenticatorForwardConfig = new(AuthenticatorBearerTokenConfiguration)

func NewAuthenticatorBearerToken(c configuration.Provider, provider trace.TracerProvider, logger *logrusx.Logger) *AuthenticatorBearerToken {
	return &AuthenticatorBearerToken{
		c: c,
		client: &http.Client{
			Transport: otelhttp.NewTransport(
				http.DefaultTransport,
				otelhttp.WithTracerProvider(provider),
			),
		},
		tracer: provider.Tracer("oauthkeeper/pipeline/authn"),
		logger: logger,
	}
}

func (a *AuthenticatorBearerToken) GetID() string {
	return "bearer_token"
}

func (a *AuthenticatorBearerToken) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorBearerToken) Config(config json.RawMessage) (*AuthenticatorBearerTokenConfiguration, error) {
	var c AuthenticatorBearerTokenConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	if len(c.ExtraFrom) == 0 {
		c.ExtraFrom = "extra"
	}

	if len(c.SubjectFrom) == 0 {
		c.SubjectFrom = "sub"
	}

	// Add Authorization and Cookie headers for backward compatibility
	c.ForwardHTTPHeaders = append(c.ForwardHTTPHeaders, []string{header.Authorization}...)

	return &c, nil
}

func (a *AuthenticatorBearerToken) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) (err error) {
	ctx, span := a.tracer.Start(r.Context(), "pipeline.authn.AuthenticatorBearerToken.Authenticate")
	defer otelx.End(span, &err)
	r = r.WithContext(ctx)

	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	token := helper.BearerTokenFromRequest(r, cf.BearerTokenLocation)
	if token == "" || !strings.HasPrefix(token, cf.Prefix) {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	body, err := a.forwardRequestToSessionStore(a.client, r, cf)
	if err != nil {
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

func (a *AuthenticatorBearerToken) forwardRequestToSessionStore(client *http.Client, r *http.Request, cf AuthenticatorForwardConfig) (json.RawMessage, error) {
	req, err := PrepareRequest(r, cf)
	if err != nil {
		a.logger.WithError(err).Error("Failed to prepare request to session store")
		return nil, err
	}

	a.logger.WithField("url", req.URL.String()).Debug("Forwarding request to session store")
	res, err := client.Do(req.WithContext(r.Context()))
	if err != nil {
		a.logger.WithError(err).Error("Failed to forward request to session store")
		return nil, helper.ErrForbidden.WithReason(err.Error()).WithTrace(err)
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			a.logger.WithError(err).Error("Failed to read response body from session store")
			return json.RawMessage{}, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch cookie session context from remote: %+v", err))
		}
		a.logger.WithField("status_code", res.StatusCode).Debug("Successfully received response from session store")
		return body, nil
	} else {
		a.logger.WithField("status_code", res.StatusCode).Debug("Received non-OK response from session store")
		return json.RawMessage{}, errors.WithStack(helper.ErrUnauthorized)
	}
}
