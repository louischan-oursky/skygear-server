package handler

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authn"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/hook"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	authModel "github.com/skygeario/skygear-server/pkg/auth/model"
	"github.com/skygeario/skygear-server/pkg/core/auth/authz"
	"github.com/skygeario/skygear-server/pkg/core/auth/authz/policy"
	"github.com/skygeario/skygear-server/pkg/core/auth/session"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/handler"
	"github.com/skygeario/skygear-server/pkg/core/inject"
	"github.com/skygeario/skygear-server/pkg/core/server"
)

// AttachLogoutHandler attach logout handler to server
func AttachLogoutHandler(
	router *mux.Router,
	authDependency auth.DependencyMap,
) {
	router.NewRoute().
		Path("/logout").
		Handler(server.FactoryToHandler(&LogoutHandlerFactory{
			authDependency,
		})).
		Methods("OPTIONS", "POST")
}

// LogoutHandlerFactory creates new handler
type LogoutHandlerFactory struct {
	Dependency auth.DependencyMap
}

// NewHandler creates new handler
func (f LogoutHandlerFactory) NewHandler(request *http.Request) http.Handler {
	h := &LogoutHandler{}
	inject.DefaultRequestInject(h, f.Dependency, request)
	return h.RequireAuthz(h, h)
}

/*
	@Operation POST /logout - Logout current session
		Logout current session.

		@Tag User
		@SecurityRequirement access_key
		@SecurityRequirement access_token

		@Response 200 {EmptyResponse}

		@Callback session_delete {SessionDeleteEvent}
		@Callback user_sync {UserSyncEvent}
*/
type LogoutHandler struct {
	RequireAuthz     handler.RequireAuthz       `dependency:"RequireAuthz"`
	UserProfileStore userprofile.Store          `dependency:"UserProfileStore"`
	IdentityProvider principal.IdentityProvider `dependency:"IdentityProvider"`
	SessionProvider  session.Provider           `dependency:"SessionProvider"`
	SessionWriter    session.Writer             `dependency:"SessionWriter"`
	HookProvider     hook.Provider              `dependency:"HookProvider"`
	TxContext        db.TxContext               `dependency:"TxContext"`
}

// ProvideAuthzPolicy provides authorization policy of handler
func (h LogoutHandler) ProvideAuthzPolicy() authz.Policy {
	return policy.RequireValidUser
}

func (h LogoutHandler) WithTx() bool {
	return true
}

// DecodeRequest decode request payload
func (h LogoutHandler) DecodeRequest(request *http.Request, resp http.ResponseWriter) (handler.RequestPayload, error) {
	payload := handler.EmptyRequestPayload{}
	err := handler.DecodeJSONBody(request, resp, &payload)
	return payload, err
}

func (h LogoutHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	result, err := handler.Transactional(h.TxContext, func() (interface{}, error) {
		return h.Handle(req)
	})
	if err == nil {
		h.SessionWriter.ClearSession(resp)
		handler.WriteResponse(resp, handler.APIResponse{Result: result})
	} else {
		handler.WriteResponse(resp, handler.APIResponse{Error: err})
	}
}

// Handle api request
func (h LogoutHandler) Handle(r *http.Request) (resp interface{}, err error) {
	authInfo := authn.GetUser(r.Context())
	sess := authn.GetSession(r.Context())

	resp = map[string]string{}

	var profile userprofile.UserProfile
	if profile, err = h.UserProfileStore.GetUserProfile(authInfo.ID); err != nil {
		return
	}

	var principal principal.Principal
	if principal, err = h.IdentityProvider.GetPrincipalByID(sess.SessionAttrs().PrincipalID); err != nil {
		return
	}

	user := authModel.NewUser(*authInfo, profile)
	identity := authModel.NewIdentity(h.IdentityProvider, principal)

	// TODO(authn): use new session provider
	_, _ = user, identity
	/*
		session := authSession.Format(sess)

		err = h.HookProvider.DispatchEvent(
			event.SessionDeleteEvent{
				Reason:   event.SessionDeleteReasonLogout,
				User:     user,
				Identity: identity,
				Session:  session,
			},
			&user,
		)
		if err != nil {
			return
		}

		if err = h.SessionProvider.Invalidate(sess); err != nil {
			return
		}
	*/

	return
}
