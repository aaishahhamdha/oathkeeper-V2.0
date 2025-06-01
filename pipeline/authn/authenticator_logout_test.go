// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"

	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/internal"
	. "github.com/aaishahhamdha/oathkeeper/pipeline/authn"
)

func TestAuthenticatorLogout(t *testing.T) {
	t.Parallel()
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistry(conf)

	a, err := reg.PipelineAuthenticator("logout")
	require.NoError(t, err)
	assert.Equal(t, "logout", a.GetID())

	t.Run("method=authenticate", func(t *testing.T) {
		for k, tc := range []struct {
			d              string
			setup          func(*testing.T, *httprouter.Router)
			r              *http.Request
			config         json.RawMessage
			expectErr      bool
			expectExactErr error
		}{
			{
				d: "should always fail with unauthorized error",
				r: &http.Request{
					Method: "GET",
					Header: http.Header{},
				},
				config:         json.RawMessage(`{}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				d: "should fail even with valid configuration",
				r: &http.Request{
					Method: "POST",
					Header: http.Header{"Authorization": {"Bearer token"}},
				},
				config: json.RawMessage(`{
					"oidc_logout_url": "https://provider.com/logout",
					"post_logout_redirect_url": "https://app.com/logged-out"
				}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				d: "should fail with any request method",
				r: &http.Request{
					Method: "DELETE",
					Header: http.Header{},
				},
				config: json.RawMessage(`{
					"oidc_logout_url": "https://provider.com/logout",
					"post_logout_redirect_url": "https://app.com/logged-out"
				}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				d: "should fail with cookies present",
				r: func() *http.Request {
					req := &http.Request{
						Method: "GET",
						Header: http.Header{},
					}
					req.AddCookie(&http.Cookie{
						Name:  "session_id",
						Value: "some_session",
					})
					return req
				}(),
				config: json.RawMessage(`{
					"oidc_logout_url": "https://provider.com/logout",
					"post_logout_redirect_url": "https://app.com/logged-out"
				}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				d: "should fail with custom headers",
				r: &http.Request{
					Method: "GET",
					Header: http.Header{
						"X-Custom-Header": {"custom-value"},
						"User-Agent":      {"test-agent"},
					},
				},
				config: json.RawMessage(`{
					"oidc_logout_url": "https://provider.com/logout",
					"post_logout_redirect_url": "https://app.com/logged-out"
				}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
		} {
			t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
				router := httprouter.New()
				if tc.setup != nil {
					tc.setup(t, router)
				}
				ts := httptest.NewServer(router)
				defer ts.Close()

				// Update config with test server URLs if needed
				if tc.config != nil {
					tc.config, _ = sjson.SetBytes(tc.config, "oidc_logout_url", ts.URL+"/logout")
				}

				sess := new(AuthenticationSession)
				err := a.Authenticate(tc.r, sess, tc.config, nil)

				if tc.expectErr {
					require.Error(t, err)
					if tc.expectExactErr != nil {
						assert.ErrorIs(t, err, tc.expectExactErr)
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("method=validate", func(t *testing.T) {
		// Enable the logout authenticator
		conf.SetForTest(t, "authenticators.logout.enabled", true)

		validConfig := json.RawMessage(`{
			"oidc_logout_url": "https://provider.com/logout",
			"post_logout_redirect_url": "https://app.com/logged-out"
		}`)
		require.NoError(t, a.Validate(validConfig))

		// Test with minimal config
		minimalConfig := json.RawMessage(`{
			"oidc_logout_url": "https://provider.com/logout"
		}`)
		require.NoError(t, a.Validate(minimalConfig))

		// Test with empty config (should still pass as logout doesn't require specific config)
		emptyConfig := json.RawMessage(`{}`)
		require.NoError(t, a.Validate(emptyConfig))

		// Test with invalid JSON
		invalidConfig := json.RawMessage(`{"oidc_logout_url": }`)
		require.Error(t, a.Validate(invalidConfig))

		// Test when authenticator is disabled
		conf.SetForTest(t, "authenticators.logout.enabled", false)
		require.Error(t, a.Validate(validConfig))
	})

	t.Run("method=GetID", func(t *testing.T) {
		assert.Equal(t, "logout", a.GetID())
	})

	t.Run("method=Config", func(t *testing.T) {
		// Test valid configuration parsing
		configJSON := json.RawMessage(`{
			"oidc_logout_url": "https://provider.com/logout",
			"post_logout_redirect_url": "https://app.com/logged-out"
		}`)

		// Access the authenticator's Config method through type assertion
		if logoutAuth, ok := a.(*AuthenticatorLogout); ok {
			config, client, err := logoutAuth.Config(configJSON)
			require.NoError(t, err)
			require.NotNil(t, config)
			require.NotNil(t, client)

			assert.Equal(t, "https://provider.com/logout", config.OidcLogoutUrl)
			assert.Equal(t, "https://app.com/logged-out", config.PostLogoutRedirectUrl)
		} else {
			t.Skip("Cannot access Config method - authenticator type assertion failed")
		}

		// Test invalid configuration
		invalidConfigJSON := json.RawMessage(`{"invalid": "json"}`)
		if logoutAuth, ok := a.(*AuthenticatorLogout); ok {
			_, _, err := logoutAuth.Config(invalidConfigJSON)
			require.Error(t, err)
		}
	})

	t.Run("behavior=always_unauthorized", func(t *testing.T) {
		// Test that the logout authenticator ALWAYS returns unauthorized
		// regardless of the request content, headers, or configuration

		testCases := []struct {
			name    string
			request *http.Request
			config  json.RawMessage
		}{
			{
				name:    "empty request",
				request: &http.Request{},
				config:  json.RawMessage(`{}`),
			},
			{
				name: "request with authorization header",
				request: &http.Request{
					Header: http.Header{"Authorization": {"Bearer valid-token"}},
				},
				config: json.RawMessage(`{}`),
			},
			{
				name: "request with session cookie",
				request: func() *http.Request {
					req := &http.Request{Header: http.Header{}}
					req.AddCookie(&http.Cookie{Name: "session", Value: "valid-session"})
					return req
				}(),
				config: json.RawMessage(`{}`),
			},
			{
				name: "POST request with body",
				request: &http.Request{
					Method: "POST",
					Header: http.Header{"Content-Type": {"application/json"}},
				},
				config: json.RawMessage(`{"oidc_logout_url": "https://provider.com/logout"}`),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				sess := new(AuthenticationSession)
				err := a.Authenticate(tc.request, sess, tc.config, nil)

				require.Error(t, err)
				assert.ErrorIs(t, err, helper.ErrUnauthorized)

				// Session should remain empty/unchanged
				assert.Empty(t, sess.Subject)
				assert.Empty(t, sess.Extra)
			})
		}
	})
}
