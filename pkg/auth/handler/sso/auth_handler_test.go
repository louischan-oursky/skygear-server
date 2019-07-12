package sso

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	coreconfig "github.com/skygeario/skygear-server/pkg/core/config"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal/password"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/sso"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	"github.com/skygeario/skygear-server/pkg/core/auth"
	"github.com/skygeario/skygear-server/pkg/core/auth/authinfo"
	"github.com/skygeario/skygear-server/pkg/core/auth/authtoken"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/skyerr"

	. "github.com/skygeario/skygear-server/pkg/core/skytest"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAuthPayload(t *testing.T) {
	Convey("Test AuthRequestPayload", t, func() {
		// callback URL and ux_mode is required
		Convey("validate valid payload", func() {
			payload := AuthRequestPayload{
				Code:         "code",
				EncodedState: "state",
			}
			So(payload.Validate(), ShouldBeNil)
		})

		Convey("validate payload without code", func() {
			payload := AuthRequestPayload{
				EncodedState: "state",
			}
			err := payload.Validate()
			errResponse := err.(skyerr.Error)
			So(errResponse.Code(), ShouldEqual, skyerr.InvalidArgument)
		})

		Convey("validate payload without state", func() {
			payload := AuthRequestPayload{
				Code: "code",
			}
			err := payload.Validate()
			errResponse := err.(skyerr.Error)
			So(errResponse.Code(), ShouldEqual, skyerr.InvalidArgument)
		})
	})
}

func TestAuthHandler(t *testing.T) {
	realTime := timeNow
	timeNow = func() time.Time { return time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC) }
	defer func() {
		timeNow = realTime
	}()

	Convey("Test AuthHandler with login action", t, func() {
		action := "login"
		stateJWTSecret := "secret"
		providerName := "mock"
		providerUserID := "mock_user_id"
		sh := &AuthHandler{}
		sh.TxContext = db.NewMockTxContext()
		sh.AuthContext = auth.NewMockContextGetterWithDefaultUser()
		oauthConfig := coreconfig.OAuthConfiguration{
			URLPrefix:      "http://localhost:3000",
			StateJWTSecret: stateJWTSecret,
			AllowedCallbackURLs: []string{
				"http://localhost",
			},
		}
		providerConfig := coreconfig.OAuthProviderConfiguration{
			ID:           providerName,
			Type:         "google",
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
		}
		mockProvider := sso.MockSSOProvider{
			BaseURL:        "http://mock/auth",
			OAuthConfig:    oauthConfig,
			ProviderConfig: providerConfig,
			UserInfo:       sso.ProviderUserInfo{ID: providerUserID},
		}
		sh.Provider = &mockProvider
		mockOAuthProvider := oauth.NewMockProvider(
			map[string]string{},
			map[string]oauth.Principal{},
		)
		sh.OAuthAuthProvider = mockOAuthProvider
		authInfoStore := authinfo.NewMockStoreWithAuthInfoMap(
			map[string]authinfo.AuthInfo{},
		)
		sh.AuthInfoStore = authInfoStore
		mockTokenStore := authtoken.NewMockStore()
		sh.TokenStore = mockTokenStore
		sh.UserProfileStore = userprofile.NewMockUserProfileStore()
		sh.AuthHandlerHTMLProvider = sso.NewAuthHandlerHTMLProvider(
			"https://api.example.com",
			"https://api.example.com/skygear.js",
		)
		sh.OAuthConfiguration = oauthConfig
		zero := 0
		one := 1
		loginIDsKeys := map[string]coreconfig.LoginIDKeyConfiguration{
			"email": coreconfig.LoginIDKeyConfiguration{Minimum: &zero, Maximum: &one},
		}
		allowedRealms := []string{password.DefaultRealm}
		passwordAuthProvider := password.NewMockProviderWithPrincipalMap(
			loginIDsKeys,
			allowedRealms,
			map[string]password.Principal{},
		)
		sh.PasswordAuthProvider = passwordAuthProvider
		sh.IdentityProvider = principal.NewMockIdentityProvider(sh.OAuthAuthProvider, sh.PasswordAuthProvider)

		Convey("should return callback url when ux_mode is web_redirect", func() {
			uxMode := sso.UXModeWebRedirect

			// oauth state
			state := sso.State{
				CallbackURL: "http://localhost:3000",
				UXMode:      uxMode,
				Action:      action,
			}
			encodedState, _ := sso.EncodeState(stateJWTSecret, state)

			v := url.Values{}
			v.Set("code", "code")
			v.Add("state", encodedState)
			u := url.URL{
				RawQuery: v.Encode(),
			}

			req, _ := http.NewRequest("GET", u.RequestURI(), nil)
			resp := httptest.NewRecorder()

			sh.ServeHTTP(resp, req)
			// for web_redirect, it should redirect to original callback url
			So(resp.Code, ShouldEqual, 302)
			So(resp.Header().Get("Location"), ShouldEqual, "http://localhost:3000")

			// check cookies
			// it should have following format
			// {
			// 	"callback_url": "callback_url"
			// 	"result": authResp
			// }
			cookies := resp.Result().Cookies()
			So(cookies, ShouldNotBeEmpty)
			var ssoDataCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "sso_data" {
					ssoDataCookie = c
					break
				}
			}
			So(ssoDataCookie, ShouldNotBeNil)

			// decoded it first
			decoded, err := base64.StdEncoding.DecodeString(ssoDataCookie.Value)
			So(err, ShouldBeNil)
			So(decoded, ShouldNotBeNil)

			// Unmarshal to map
			data := make(map[string]interface{})
			err = json.Unmarshal(decoded, &data)
			So(err, ShouldBeNil)

			// check callback_url
			So(data["callback_url"], ShouldEqual, "http://localhost:3000")

			// check result(authResp)
			authResp, err := json.Marshal(data["result"])
			So(err, ShouldBeNil)
			p, err := sh.OAuthAuthProvider.GetPrincipalByProviderUserID(providerName, providerUserID)
			So(err, ShouldBeNil)
			token := mockTokenStore.GetTokensByAuthInfoID(p.UserID)[0]
			So(authResp, ShouldEqualJSON, fmt.Sprintf(`{
				"result": {
					"user": {
						"id": "%s",
						"is_verified": false,
						"is_disabled": false,
						"last_login_at": "2006-01-02T15:04:05Z",
						"created_at": "0001-01-01T00:00:00Z",
						"verify_info": {},
						"metadata": {}
					},
					"identity": {
						"id": "%s",
						"type": "oauth",
						"provider_id": "mock",
						"provider_user_id": "mock_user_id",
						"raw_profile": {},
						"claims": {}
					},
					"access_token": "%s"
				}
			}`,
				p.UserID,
				p.ID,
				token.AccessToken))
		})

		Convey("should return html page when ux_mode is web_popup", func() {
			uxMode := sso.UXModeWebPopup

			// oauth state
			state := sso.State{
				CallbackURL: "http://localhost:3000",
				UXMode:      uxMode,
				Action:      action,
			}
			encodedState, _ := sso.EncodeState(stateJWTSecret, state)

			v := url.Values{}
			v.Set("code", "code")
			v.Add("state", encodedState)
			u := url.URL{
				RawQuery: v.Encode(),
			}

			req, _ := http.NewRequest("GET", u.RequestURI(), nil)
			resp := httptest.NewRecorder()

			sh.ServeHTTP(resp, req)
			// for web_redirect, it should redirect to original callback url
			So(resp.Code, ShouldEqual, 200)
			JSSKDURLPattern := `<script type="text/javascript" src="https://api.example.com/skygear.js"></script>`
			matched, err := regexp.MatchString(JSSKDURLPattern, resp.Body.String())
			So(err, ShouldBeNil)
			So(matched, ShouldBeTrue)
		})

		Convey("should return callback url with result query parameter when ux_mode is ios or android", func() {
			uxMode := sso.UXModeIOS

			// oauth state
			state := sso.State{
				CallbackURL: "http://localhost:3000",
				UXMode:      uxMode,
				Action:      action,
			}
			encodedState, _ := sso.EncodeState(stateJWTSecret, state)

			v := url.Values{}
			v.Set("code", "code")
			v.Add("state", encodedState)
			u := url.URL{
				RawQuery: v.Encode(),
			}

			req, _ := http.NewRequest("GET", u.RequestURI(), nil)
			resp := httptest.NewRecorder()

			sh.ServeHTTP(resp, req)
			// for ios or android, it should redirect to original callback url
			So(resp.Code, ShouldEqual, 302)
			// check location result query parameter
			location, _ := url.Parse(resp.Header().Get("Location"))
			q := location.Query()
			result := q.Get("result")
			decoded, _ := base64.StdEncoding.DecodeString(result)
			p, _ := sh.OAuthAuthProvider.GetPrincipalByProviderUserID(providerName, providerUserID)
			token := mockTokenStore.GetTokensByAuthInfoID(p.UserID)[0]
			So(decoded, ShouldEqualJSON, fmt.Sprintf(`{
				"result": {
					"user": {
						"id": "%s",
						"is_verified": false,
						"is_disabled": false,
						"last_login_at": "2006-01-02T15:04:05Z",
						"created_at": "0001-01-01T00:00:00Z",
						"verify_info": {},
						"metadata": {}
					},
					"identity": {
						"id": "%s",
						"type": "oauth",
						"provider_id": "mock",
						"provider_user_id": "mock_user_id",
						"raw_profile": {},
						"claims": {}
					},
					"access_token": "%s"
				}
			}`,
				p.UserID,
				p.ID,
				token.AccessToken))
		})
	})

	Convey("Test AuthHandler with link action", t, func() {
		action := "link"
		stateJWTSecret := "secret"
		sh := &AuthHandler{}
		sh.TxContext = db.NewMockTxContext()
		sh.AuthContext = auth.NewMockContextGetterWithDefaultUser()
		oauthConfig := coreconfig.OAuthConfiguration{
			URLPrefix:      "http://localhost:3000",
			StateJWTSecret: stateJWTSecret,
			AllowedCallbackURLs: []string{
				"http://localhost",
			},
		}
		providerConfig := coreconfig.OAuthProviderConfiguration{
			ID:           "mock",
			Type:         "google",
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
		}
		mockProvider := sso.MockSSOProvider{
			BaseURL:        "http://mock/auth",
			OAuthConfig:    oauthConfig,
			ProviderConfig: providerConfig,
		}
		sh.Provider = &mockProvider
		mockOAuthProvider := oauth.NewMockProvider(
			map[string]string{
				"jane.doe.id": "jane.doe.id",
			},
			map[string]oauth.Principal{
				"jane.doe.id": oauth.Principal{},
			},
		)
		sh.OAuthAuthProvider = mockOAuthProvider
		authInfoStore := authinfo.NewMockStoreWithAuthInfoMap(
			map[string]authinfo.AuthInfo{
				"john.doe.id": authinfo.AuthInfo{
					ID: "john.doe.id",
				},
				"jane.doe.id": authinfo.AuthInfo{
					ID: "jane.doe.id",
				},
			},
		)
		sh.AuthInfoStore = authInfoStore
		mockTokenStore := authtoken.NewMockStore()
		sh.TokenStore = mockTokenStore
		sh.AuthHandlerHTMLProvider = sso.NewAuthHandlerHTMLProvider(
			"https://api.example.com",
			"https://api.example.com/skygear.js",
		)
		sh.OAuthConfiguration = oauthConfig
		zero := 0
		one := 1
		loginIDsKeys := map[string]coreconfig.LoginIDKeyConfiguration{
			"email": coreconfig.LoginIDKeyConfiguration{Minimum: &zero, Maximum: &one},
		}
		allowedRealms := []string{password.DefaultRealm}
		passwordAuthProvider := password.NewMockProviderWithPrincipalMap(
			loginIDsKeys,
			allowedRealms,
			map[string]password.Principal{},
		)
		sh.PasswordAuthProvider = passwordAuthProvider
		sh.IdentityProvider = principal.NewMockIdentityProvider(sh.OAuthAuthProvider, sh.PasswordAuthProvider)

		Convey("should return callback url when ux_mode is web_redirect", func() {
			uxMode := sso.UXModeWebRedirect

			// oauth state
			state := sso.State{
				CallbackURL: "http://localhost:3000",
				UXMode:      uxMode,
				Action:      action,
				UserID:      "john.doe.id",
			}
			encodedState, _ := sso.EncodeState(stateJWTSecret, state)

			v := url.Values{}
			v.Set("code", "code")
			v.Add("state", encodedState)
			u := url.URL{
				RawQuery: v.Encode(),
			}

			req, _ := http.NewRequest("GET", u.RequestURI(), nil)
			resp := httptest.NewRecorder()

			sh.ServeHTTP(resp, req)
			// for web_redirect, it should redirect to original callback url
			So(resp.Code, ShouldEqual, 302)
			So(resp.Header().Get("Location"), ShouldEqual, "http://localhost:3000")

			// check cookies
			// it should have following format
			// {
			// 	"callback_url": "callback_url"
			// 	"result": authResp
			// }
			cookies := resp.Result().Cookies()
			So(cookies, ShouldNotBeEmpty)
			var ssoDataCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "sso_data" {
					ssoDataCookie = c
					break
				}
			}
			So(ssoDataCookie, ShouldNotBeNil)

			// decoded it first
			decoded, err := base64.StdEncoding.DecodeString(ssoDataCookie.Value)
			So(err, ShouldBeNil)
			So(decoded, ShouldNotBeNil)

			// Unmarshal to map
			data := make(map[string]interface{})
			err = json.Unmarshal(decoded, &data)
			So(err, ShouldBeNil)

			// check callback_url
			So(data["callback_url"], ShouldEqual, "http://localhost:3000")

			// check result(resp)
			result, err := json.Marshal(data["result"])
			So(err, ShouldBeNil)
			So(string(result), ShouldEqualJSON, `{
				"result": {}
			}`)
		})

		Convey("should get err if user is already linked", func() {
			uxMode := sso.UXModeWebRedirect

			// oauth state
			state := sso.State{
				CallbackURL: "http://localhost:3000",
				UXMode:      uxMode,
				Action:      action,
				UserID:      "jane.doe.id",
			}
			encodedState, _ := sso.EncodeState(stateJWTSecret, state)

			v := url.Values{}
			v.Set("code", "code")
			v.Add("state", encodedState)
			u := url.URL{
				RawQuery: v.Encode(),
			}

			req, _ := http.NewRequest("GET", u.RequestURI(), nil)
			resp := httptest.NewRecorder()

			sh.ServeHTTP(resp, req)
			So(resp.Code, ShouldEqual, 302)
			So(resp.Header().Get("Location"), ShouldEqual, "http://localhost:3000")

			// check cookies
			// it should have following format
			// {
			// 	"callback_url": "callback_url"
			// 	"result": errorAuthResp
			// }
			cookies := resp.Result().Cookies()
			So(cookies, ShouldNotBeEmpty)
			var ssoDataCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "sso_data" {
					ssoDataCookie = c
					break
				}
			}
			So(ssoDataCookie, ShouldNotBeNil)

			// decoded it first
			decoded, err := base64.StdEncoding.DecodeString(ssoDataCookie.Value)
			So(err, ShouldBeNil)
			So(decoded, ShouldNotBeNil)

			// Unmarshal to map
			data := make(map[string]interface{})
			err = json.Unmarshal(decoded, &data)
			So(err, ShouldBeNil)

			// check callback_url
			So(data["callback_url"], ShouldEqual, "http://localhost:3000")

			// check result(resp)
			result, err := json.Marshal(data["result"])
			So(err, ShouldBeNil)
			So(string(result), ShouldEqualJSON, `{
				"error":{"code":108,"message":"provider account already linked with existing user","name":"InvalidArgument"}
			}`)
		})
	})

	/*
		Convey("Test AuthHandler's auto link procedure", t, func() {
			action := "login"
			UXMode := "web_redirect"

			stateJWTSecret := "secret"
			providerName := "mock"
			providerUserID := "mock_user_id"
			sh := &AuthHandler{}
			sh.TxContext = db.NewMockTxContext()
			sh.AuthContext = auth.NewMockContextGetterWithDefaultUser()
			oauthConfig := coreconfig.OAuthConfiguration{
				URLPrefix:      "http://localhost:3000",
				StateJWTSecret: stateJWTSecret,
				// AutoLinkEnabled: true,
				AllowedCallbackURLs: []string{
					"http://localhost",
				},
			}
			providerConfig := coreconfig.OAuthProviderConfiguration{
				ID:           providerName,
				Type:         "google",
				ClientID:     "mock_client_id",
				ClientSecret: "mock_client_secret",
			}
			mockProvider := sso.MockSSOProvider{
				BaseURL:        "http://mock/auth",
				OAuthConfig:    oauthConfig,
				ProviderConfig: providerConfig,
				UserInfo: sso.ProviderUserInfo{ID: providerUserID,
					Email: "john.doe@example.com"},
			}
			sh.Provider = &mockProvider
			mockOAuthProvider := oauth.NewMockProvider(
				map[string]string{},
				map[string]oauth.Principal{},
			)
			sh.OAuthAuthProvider = mockOAuthProvider
			authInfoStore := authinfo.NewMockStoreWithAuthInfoMap(
				map[string]authinfo.AuthInfo{
					"john.doe.id": authinfo.AuthInfo{
						ID: "john.doe.id",
					},
				},
			)
			sh.AuthInfoStore = authInfoStore
			mockTokenStore := authtoken.NewMockStore()
			sh.TokenStore = mockTokenStore
			profileData := map[string]map[string]interface{}{
				"john.doe.id": map[string]interface{}{},
			}
			sh.UserProfileStore = userprofile.NewMockUserProfileStoreByData(profileData)
			sh.AuthHandlerHTMLProvider = sso.NewAuthHandlerHTMLProvider(
				"https://api.example.com",
				"https://api.example.com/skygear.js",
			)
			sh.OAuthConfiguration = oauthConfig
			zero := 0
			one := 1
			loginIDsKeys := map[string]coreconfig.LoginIDKeyConfiguration{
				"email": coreconfig.LoginIDKeyConfiguration{
					Type:    coreconfig.LoginIDKeyType(metadata.Email),
					Minimum: &zero,
					Maximum: &one,
				},
			}
			allowedRealms := []string{password.DefaultRealm}
			passwordAuthProvider := password.NewMockProviderWithPrincipalMap(
				loginIDsKeys,
				allowedRealms,
				map[string]password.Principal{
					"john.doe.principal.id": password.Principal{
						ID:             "john.doe.principal.id",
						UserID:         "john.doe.id",
						LoginIDKey:     "email",
						LoginID:        "john.doe@example.com",
						Realm:          "default",
						HashedPassword: []byte("$2a$10$/jm/S1sY6ldfL6UZljlJdOAdJojsJfkjg/pqK47Q8WmOLE19tGWQi"), // 123456
					},
				},
			)
			sh.PasswordAuthProvider = passwordAuthProvider
			sh.IdentityProvider = principal.NewMockIdentityProvider(sh.OAuthAuthProvider, sh.PasswordAuthProvider)

			Convey("should auto-link password principal", func() {
				// oauth state
				state := sso.State{
					CallbackURL: "http://localhost:3000",
					UXMode:      UXMode,
					Action:      action,
				}
				encodedState, _ := sso.EncodeState(stateJWTSecret, state)

				v := url.Values{}
				v.Set("code", "code")
				v.Add("state", encodedState)
				u := url.URL{
					RawQuery: v.Encode(),
				}

				req, _ := http.NewRequest("GET", u.RequestURI(), nil)
				resp := httptest.NewRecorder()

				sh.ServeHTTP(resp, req)

				oauthPrincipal, err := sh.OAuthAuthProvider.GetPrincipalByProviderUserID(providerName, providerUserID)
				So(err, ShouldBeNil)
				So(oauthPrincipal.UserID, ShouldEqual, "john.doe.id")
			})
		})
	*/

	/*
		Convey("Test AuthHandler's auto link procedure", t, func() {
			action := "login"
			UXMode := "web_redirect"

			stateJWTSecret := "secret"
			providerName := "mock"
			providerUserID := "mock_user_id"
			sh := &AuthHandler{}
			sh.TxContext = db.NewMockTxContext()
			sh.AuthContext = auth.NewMockContextGetterWithDefaultUser()
			oauthConfig := coreconfig.OAuthConfiguration{
				URLPrefix:      "http://localhost:3000",
				StateJWTSecret: stateJWTSecret,
				// AutoLinkEnabled: true,
				AllowedCallbackURLs: []string{
					"http://localhost",
				},
			}
			providerConfig := coreconfig.OAuthProviderConfiguration{
				ID:           providerName,
				Type:         "google",
				ClientID:     "mock_client_id",
				ClientSecret: "mock_client_secret",
			}
			mockProvider := sso.MockSSOProvider{
				BaseURL:        "http://mock/auth",
				OAuthConfig:    oauthConfig,
				ProviderConfig: providerConfig,
				UserInfo: sso.ProviderUserInfo{ID: providerUserID,
					Email: "john.doe@example.com"},
			}
			sh.Provider = &mockProvider
			mockOAuthProvider := oauth.NewMockProvider(
				map[string]string{},
				map[string]oauth.Principal{},
			)
			sh.OAuthAuthProvider = mockOAuthProvider
			authInfoStore := authinfo.NewMockStoreWithAuthInfoMap(
				map[string]authinfo.AuthInfo{
					"john.doe.id": authinfo.AuthInfo{
						ID: "john.doe.id",
					},
				},
			)
			sh.AuthInfoStore = authInfoStore
			mockTokenStore := authtoken.NewMockStore()
			sh.TokenStore = mockTokenStore
			profileData := map[string]map[string]interface{}{
				"john.doe.id": map[string]interface{}{},
			}
			sh.UserProfileStore = userprofile.NewMockUserProfileStoreByData(profileData)
			sh.AuthHandlerHTMLProvider = sso.NewAuthHandlerHTMLProvider(
				"https://api.example.com",
				"https://api.example.com/skygear.js",
			)
			sh.OAuthConfiguration = oauthConfig
			// providerLoginID wouldn't match loginIDsKeys username
			zero := 0
			one := 1
			loginIDsKeys := map[string]coreconfig.LoginIDKeyConfiguration{
				"username": coreconfig.LoginIDKeyConfiguration{Minimum: &zero, Maximum: &one},
			}
			allowedRealms := []string{password.DefaultRealm}
			passwordAuthProvider := password.NewMockProviderWithPrincipalMap(
				loginIDsKeys,
				allowedRealms,
				map[string]password.Principal{
					"john.doe.principal.id": password.Principal{
						ID:             "john.doe.principal.id",
						UserID:         "john.doe.id",
						LoginIDKey:     "username",
						LoginID:        "john.doe",
						HashedPassword: []byte("$2a$10$/jm/S1sY6ldfL6UZljlJdOAdJojsJfkjg/pqK47Q8WmOLE19tGWQi"), // 123456
					},
				},
			)
			sh.PasswordAuthProvider = passwordAuthProvider
			sh.IdentityProvider = principal.NewMockIdentityProvider(sh.OAuthAuthProvider, sh.PasswordAuthProvider)

			Convey("shouldn't auto-link password principal if loginIDsKeys not matched", func() {
				// oauth state
				state := sso.State{
					CallbackURL: "http://localhost:3000",
					UXMode:      UXMode,
					Action:      action,
				}
				encodedState, _ := sso.EncodeState(stateJWTSecret, state)

				v := url.Values{}
				v.Set("code", "code")
				v.Add("state", encodedState)
				u := url.URL{
					RawQuery: v.Encode(),
				}

				req, _ := http.NewRequest("GET", u.RequestURI(), nil)
				resp := httptest.NewRecorder()

				sh.ServeHTTP(resp, req)

				oauthPrincipal, err := sh.OAuthAuthProvider.GetPrincipalByProviderUserID(providerName, providerUserID)
				So(err, ShouldBeNil)
				// should signup a new user
				So(oauthPrincipal.UserID, ShouldNotEqual, "john.doe.id")
				// empty password should not be created
				_, err = sh.PasswordAuthProvider.GetPrincipalsByUserID(oauthPrincipal.UserID)
				So(err, ShouldNotBeNil)
			})
		})
	*/
}

func TestValidateCallbackURL(t *testing.T) {
	Convey("Test ValidateCallbackURL", t, func() {
		sh := &AuthHandler{}
		callbackURL := "http://localhost:3000"
		allowedCallbackURLs := []string{
			"http://localhost",
			"http://127.0.0.1",
		}

		e := sh.validateCallbackURL(allowedCallbackURLs, callbackURL)
		So(e, ShouldBeNil)

		callbackURL = "http://oursky"
		e = sh.validateCallbackURL(allowedCallbackURLs, callbackURL)
		So(e, ShouldNotBeNil)

		e = sh.validateCallbackURL(allowedCallbackURLs, "")
		So(e, ShouldNotBeNil)
	})
}
