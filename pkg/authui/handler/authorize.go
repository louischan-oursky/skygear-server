package handler

import (
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/skygeario/skygear-server/pkg/core/auth/hook"
	"github.com/skygeario/skygear-server/pkg/core/db"
	coreHttp "github.com/skygeario/skygear-server/pkg/core/http"
	"github.com/skygeario/skygear-server/pkg/core/oauth"

	"github.com/skygeario/skygear-server/pkg/authui/inject"
	"github.com/skygeario/skygear-server/pkg/authui/provider"
	"github.com/skygeario/skygear-server/pkg/authui/template"
)

type AuthorizeHandler struct {
	ValidateProvider       provider.ValidateProvider
	RenderProvider         provider.RenderProvider
	AuthContextProvider    provider.AuthContextProvider
	AuthenticationProvider provider.AuthenticationProvider
	TxContext              db.TxContext
	HookProvider           hook.Provider
}

func NewAuthorizeHandler(
	validateProvider provider.ValidateProvider,
	renderProvider provider.RenderProvider,
	authContextProvider provider.AuthContextProvider,
	authenticationProvider provider.AuthenticationProvider,
	txContext db.TxContext,
	hookProvider hook.Provider,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		ValidateProvider:       validateProvider,
		RenderProvider:         renderProvider,
		AuthContextProvider:    authContextProvider,
		AuthenticationProvider: authenticationProvider,
		TxContext:              txContext,
		HookProvider:           hookProvider,
	}
}

func AttachAuthorizeHandler(router *mux.Router, dep *inject.BootTimeDependency) {
	router.Path("/authorize").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		InjectAuthorizeHandler(r, dep).ServeHTTP(w, r)
	}).
		// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		// Must support either POST or GET and the actual HTTP method
		// does not matter
		Methods("POST", "GET")
}

const AuthorizeRequestSchema = `
{
	"$id": "#AuthorizeRequest",
	"type": "object",
	"properties": {
		"scope": { "type": "string", "const": "openid" },
		"response_type": { "type": "string", "const": "code" },
		"client_id": { "type": "string" },
		"redirect_uri": { "type": "string" },
		"code_challenge_method": { "type": "string", "const": "S256" },
		"code_challenge": { "type": "string" },
		"x_login_id_input_type": { "type": "string", "enum": ["phone", "text"] }
	},
	"required": ["scope", "response_type", "client_id", "redirect_uri", "code_challenge_method", "code_challenge"]
}
`

const AuthorizeLoginIDRequestSchema = `
{
	"$id": "#AuthorizeLoginIDRequest",
	"type": "object",
	"properties": {
		"scope": { "type": "string", "const": "openid" },
		"response_type": { "type": "string", "const": "code" },
		"client_id": { "type": "string" },
		"redirect_uri": { "type": "string" },
		"code_challenge_method": { "type": "string", "const": "S256" },
		"code_challenge": { "type": "string" },
		"x_login_id_input_type": { "type": "string", "enum": ["phone", "text"] },
		"x_step": { "type": "string", "const": "submit_login_id" },
		"x_calling_code": { "type": "string" },
		"x_national_number": { "type": "string" },
		"x_login_id": { "type": "string" }
	},
	"required": ["scope", "response_type", "client_id", "redirect_uri", "code_challenge_method", "code_challenge", "x_login_id_input_type", "x_step"],
	"oneOf": [
	{
		"properties": {
			"x_login_id_input_type": { "type": "string", "const": "phone" }
		},
		"required": ["x_calling_code", "x_national_number"]
	},
	{
		"properties": {
			"x_login_id_input_type": { "type": "string", "const": "text" }
		},
		"required": ["x_login_id"]
	}
	]
}
`

// nolint: gosec
const AuthorizeEnterPasswordRequestSchema = `
{
	"$id": "#AuthorizeEnterPasswordRequest",
	"type": "object",
	"properties": {
		"scope": { "type": "string", "const": "openid" },
		"response_type": { "type": "string", "const": "code" },
		"client_id": { "type": "string" },
		"redirect_uri": { "type": "string" },
		"code_challenge_method": { "type": "string", "const": "S256" },
		"code_challenge": { "type": "string" },
		"x_login_id_input_type": { "type": "string", "enum": ["phone", "text"] },
		"x_step": { "type": "string", "const": "submit_password" },
		"x_calling_code": { "type": "string" },
		"x_national_number": { "type": "string" },
		"x_login_id": { "type": "string" },
		"x_password": { "type": "string" }
	},
	"required": ["scope", "response_type", "client_id", "redirect_uri", "code_challenge_method", "code_challenge", "x_login_id_input_type", "x_step", "x_password"],
	"oneOf": [
	{
		"properties": {
			"x_login_id_input_type": { "type": "string", "const": "phone" }
		},
		"required": ["x_calling_code", "x_national_number"]
	},
	{
		"properties": {
			"x_login_id_input_type": { "type": "string", "const": "text" }
		},
		"required": ["x_login_id"]
	}
	]
}
`

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}

	h.AuthContextProvider.Init(r)

	h.ValidateProvider.Prevalidate(r.Form)

	var writeResponse func(err error)
	err := hook.WithTx(h.HookProvider, h.TxContext, func() (err error) {
		step := r.Form.Get("x_step")
		switch step {
		case "submit_password":
			writeResponse, err = h.SubmitPassword(w, r)
		case "submit_login_id":
			writeResponse, err = h.SubmitLoginID(w, r)
		default:
			writeResponse, err = h.Default(w, r)
		}
		return err
	})
	writeResponse(err)
}

func (h *AuthorizeHandler) Default(w http.ResponseWriter, r *http.Request) (writeResponse func(err error), err error) {
	data := provider.FormToJSON(r.Form)
	err = h.ValidateProvider.Validate("#AuthorizeRequest", data)
	writeResponse = func(err error) {
		t := template.TemplateItemTypeAuthUIAuthorizeHTML
		h.RenderProvider.WritePage(w, r, t, data, err)
	}
	return
}

func (h *AuthorizeHandler) SubmitLoginID(w http.ResponseWriter, r *http.Request) (writeResponse func(err error), err error) {
	data := provider.FormToJSON(r.Form)
	err = h.ValidateProvider.Validate("#AuthorizeLoginIDRequest", data)
	writeResponse = func(err error) {
		t := template.TemplateItemTypeAuthUIAuthorizeHTML
		if err == nil {
			t = template.TemplateItemTypeAuthUIEnterPasswordHTML
		}
		h.RenderProvider.WritePage(w, r, t, data, err)
	}
	return
}

func (h *AuthorizeHandler) SubmitPassword(w http.ResponseWriter, r *http.Request) (writeResponse func(err error), err error) {
	var accessToken *http.Cookie
	var redirectURI *url.URL
	data := provider.FormToJSON(r.Form)
	writeResponse = func(err error) {
		if err != nil {
			t := template.TemplateItemTypeAuthUIEnterPasswordHTML
			h.RenderProvider.WritePage(w, r, t, data, err)
		} else {
			coreHttp.UpdateCookie(w, accessToken)
			http.Redirect(w, r, redirectURI.String(), http.StatusFound)
		}
	}

	err = h.ValidateProvider.Validate("#AuthorizeEnterPasswordRequest", data)
	if err != nil {
		return
	}

	loginID := provider.DeriveLoginID(r.Form)
	password := r.Form.Get("x_password")
	authnSession, err := h.AuthenticationProvider.AuthenticateWithPassword(loginID, password)
	if err != nil {
		return
	}

	// TODO(authui): Handle MFA
	if !authnSession.IsFinished() {
		panic("TODO(authui): Handle MFA")
	}

	var code string
	accessToken, code, err = h.AuthenticationProvider.Finish(r.Form, authnSession)
	if err != nil {
		return
	}

	redirectURI, err = oauth.NewAuthenticationResponse(r.Form, code)
	if err != nil {
		return
	}

	return
}
