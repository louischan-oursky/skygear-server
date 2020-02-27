package provider

import (
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"

	"github.com/skygeario/skygear-server/pkg/authui/inject"
	"github.com/skygeario/skygear-server/pkg/core/audit"
	coreAuth "github.com/skygeario/skygear-server/pkg/core/auth"
	"github.com/skygeario/skygear-server/pkg/core/auth/authinfo"
	"github.com/skygeario/skygear-server/pkg/core/auth/authnsession"
	"github.com/skygeario/skygear-server/pkg/core/auth/authorizationcode"
	"github.com/skygeario/skygear-server/pkg/core/auth/event"
	"github.com/skygeario/skygear-server/pkg/core/auth/hook"
	"github.com/skygeario/skygear-server/pkg/core/auth/mfa"
	"github.com/skygeario/skygear-server/pkg/core/auth/model/format"
	"github.com/skygeario/skygear-server/pkg/core/auth/modelprovider"
	"github.com/skygeario/skygear-server/pkg/core/auth/principal"
	"github.com/skygeario/skygear-server/pkg/core/auth/principal/password"
	"github.com/skygeario/skygear-server/pkg/core/auth/session"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/errors"
	coreHttp "github.com/skygeario/skygear-server/pkg/core/http"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/loginid"
	coreTime "github.com/skygeario/skygear-server/pkg/core/time"
)

type AuthenticationProviderImpl struct {
	PasswordAuthProvider               password.Provider
	AuditTrail                         audit.Trail
	Logger                             *logrus.Entry
	TimeProvider                       coreTime.Provider
	AuthContextProvider                AuthContextProvider
	MFAProvider                        mfa.Provider
	MFAConfiguration                   *config.MFAConfiguration
	AuthenticationSessionConfiguration *config.AuthenticationSessionConfiguration
	AuthInfoStore                      authinfo.Store
	HookProvider                       hook.Provider
	SessionProvider                    session.Provider
	ModelProvider                      modelprovider.Provider
	AuthorizationCodeStore             authorizationcode.Store
	UseInsecureCookie                  bool
}

var _ AuthenticationProvider = &AuthenticationProviderImpl{}

func NewAuthenticationProvider(
	passwordAuthProvider password.Provider,
	auditTrail audit.Trail,
	loggerFactory logging.Factory,
	timeProvider coreTime.Provider,
	authContextProvider AuthContextProvider,
	mfaProvider mfa.Provider,
	tConfig *config.TenantConfiguration,
	authInfoStore authinfo.Store,
	hookProvider hook.Provider,
	sessionProvider session.Provider,
	modelProvider modelprovider.Provider,
	authorizationCodeStore authorizationcode.Store,
	useInsecureCookie inject.UseInsecureCookie,
) *AuthenticationProviderImpl {
	return &AuthenticationProviderImpl{
		PasswordAuthProvider:               passwordAuthProvider,
		AuditTrail:                         auditTrail,
		Logger:                             loggerFactory.NewLogger("authentication-provider"),
		TimeProvider:                       timeProvider,
		AuthContextProvider:                authContextProvider,
		MFAProvider:                        mfaProvider,
		MFAConfiguration:                   tConfig.AppConfig.MFA,
		AuthenticationSessionConfiguration: tConfig.AppConfig.Auth.AuthenticationSession,
		AuthInfoStore:                      authInfoStore,
		HookProvider:                       hookProvider,
		SessionProvider:                    sessionProvider,
		ModelProvider:                      modelProvider,
		AuthorizationCodeStore:             authorizationCodeStore,
		UseInsecureCookie:                  bool(useInsecureCookie),
	}
}

func (p *AuthenticationProviderImpl) FromToken(token string) (*coreAuth.AuthnSession, error) {
	claims, err := coreAuth.ParseAuthnSessionToken(p.AuthenticationSessionConfiguration.Secret, token)
	if err != nil {
		return nil, err
	}
	return &claims.AuthnSession, nil
}

func (p *AuthenticationProviderImpl) ToToken(authnSession *coreAuth.AuthnSession) (token string, err error) {
	now := p.TimeProvider.NowUTC()
	expiresAt := now.Add(5 * time.Minute)
	claims := coreAuth.AuthnSessionClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  now.Unix(),
		},
		AuthnSession: *authnSession,
	}
	token, err = coreAuth.NewAuthnSessionToken(p.AuthenticationSessionConfiguration.Secret, claims)
	if err != nil {
		return
	}
	return
}

func (p *AuthenticationProviderImpl) AuthenticateWithPassword(loginID string, plainPassword string) (authnSession *coreAuth.AuthnSession, err error) {
	var userID string

	defer func() {
		if userID != "" {
			if err != nil {
				p.AuditTrail.Log(audit.Entry{
					UserID: userID,
					Event:  audit.EventLoginFailure,
				})
			} else {
				p.AuditTrail.Log(audit.Entry{
					UserID: userID,
					Event:  audit.EventLoginSuccess,
				})
			}
		}
	}()

	var prin password.Principal
	err = p.PasswordAuthProvider.GetPrincipalByLoginIDWithRealm("", loginID, loginid.DefaultRealm, &prin)
	if err != nil {
		if errors.Is(err, principal.ErrNotFound) {
			err = password.ErrInvalidCredentials
		}
		if errors.Is(err, principal.ErrMultipleResultsFound) {
			p.Logger.WithError(err).Warn("Multiple results found for password principal query")
			err = password.ErrInvalidCredentials
		}
		return
	}
	userID = prin.UserID

	err = prin.VerifyPassword(plainPassword)
	if err != nil {
		return
	}

	// This err is non-critical
	if err := p.PasswordAuthProvider.MigratePassword(&prin, plainPassword); err != nil {
		p.Logger.WithError(err).Error("Failed to migrate password")
	}

	now := p.TimeProvider.NowUTC()
	requiredSteps, err := authnsession.GetRequiredSteps(p.MFAProvider, p.MFAConfiguration, userID)
	if err != nil {
		err = errors.HandledWithMessage(err, "cannot get required authn steps")
		return
	}

	// Identity is considered finished here.
	finishedSteps := requiredSteps[:1]
	authnSession = &coreAuth.AuthnSession{
		// No client ID
		ClientID:            "",
		UserID:              userID,
		PrincipalID:         prin.PrincipalID(),
		PrincipalType:       coreAuth.PrincipalType(prin.ProviderID()),
		PrincipalUpdatedAt:  now,
		RequiredSteps:       requiredSteps,
		FinishedSteps:       finishedSteps,
		SessionCreateReason: coreAuth.SessionCreateReasonLogin,
	}

	return
}

func (p *AuthenticationProviderImpl) Finish(form url.Values, authnSession *coreAuth.AuthnSession) (accessToken *http.Cookie, code string, err error) {
	user, err := p.ModelProvider.GetUser(authnSession.UserID)
	if err != nil {
		return
	}
	identity, err := p.ModelProvider.GetIdentity(authnSession.PrincipalID)
	if err != nil {
		return
	}
	beforeCreate := func(sess *coreAuth.Session) error {
		sessionModel := format.SessionFromSession(sess)
		return p.HookProvider.DispatchEvent(
			event.SessionCreateEvent{
				Reason:   coreAuth.SessionCreateReason(authnSession.SessionCreateReason),
				User:     *user,
				Identity: *identity,
				Session:  sessionModel,
			},
			user,
		)
	}
	_, tokens, err := p.SessionProvider.Create(authnSession, beforeCreate)
	if err != nil {
		return
	}
	// TODO(authui): Use session token instead access token
	accessToken = &http.Cookie{
		Name:     coreHttp.CookieNameSession,
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   !p.UseInsecureCookie,
	}

	// Update LastLoginAt and LastSeenAt
	now := p.TimeProvider.NowUTC()
	var authInfo authinfo.AuthInfo
	err = p.AuthInfoStore.GetAuth(authnSession.UserID, &authInfo)
	if err != nil {
		return
	}
	authInfo.LastLoginAt = &now
	authInfo.LastSeenAt = &now
	authInfo.RefreshDisabledStatus()
	err = p.AuthInfoStore.UpdateAuth(&authInfo)
	if err != nil {
		return
	}

	code, err = p.AuthorizationCodeStore.New(authorizationcode.New(form, authnSession))
	if err != nil {
		return
	}

	return
}
