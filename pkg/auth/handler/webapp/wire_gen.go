// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package webapp

import (
	"github.com/google/wire"
	"github.com/gorilla/mux"
	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/audit"
	auth2 "github.com/skygeario/skygear-server/pkg/auth/dependency/auth"
	redis2 "github.com/skygeario/skygear-server/pkg/auth/dependency/auth/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/authn"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/hook"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/loginid"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/mfa"
	pq3 "github.com/skygeario/skygear-server/pkg/auth/dependency/mfa/pq"
	oauth2 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/handler"
	pq4 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/pq"
	redis3 "github.com/skygeario/skygear-server/pkg/auth/dependency/oauth/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/oidc"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/passwordhistory/pq"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/principal/password"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/session"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/session/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/sso"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/urlprefix"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/webapp"
	"github.com/skygeario/skygear-server/pkg/core/async"
	pq2 "github.com/skygeario/skygear-server/pkg/core/auth/authinfo/pq"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/mail"
	"github.com/skygeario/skygear-server/pkg/core/sms"
	"github.com/skygeario/skygear-server/pkg/core/time"
	"net/http"
)

// Injectors from wire.go:

func newLoginHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	validateProvider := webapp.ProvideValidateProvider(tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, provider, passwordProvider, oauthProvider, identityProvider)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, provider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	authorizationCodeStore := authn.ProvideAuthorizationCodeStore(context)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:                  authenticateProcess,
		Signup:                 signupProcess,
		AuthorizationCodeStore: authorizationCodeStore,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, provider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, provider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, provider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthUIProvider(providerFactory)
	stateStoreImpl := &webapp.StateStoreImpl{
		Context: context,
	}
	provider2 := sso.ProvideSSOProvider(context, tenantConfiguration)
	authenticateProviderImpl := &webapp.AuthenticateProviderImpl{
		ValidateProvider: validateProvider,
		RenderProvider:   renderProvider,
		AuthnProvider:    authnProvider,
		StateStore:       stateStoreImpl,
		SSOProvider:      provider2,
	}
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := provideRedirectURIForWebAppFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, provider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromLoginForm(r, oAuthProviderFactory)
	loginHandler := &LoginHandler{
		Provider:      authenticateProviderImpl,
		oauthProvider: oAuthProvider,
	}
	return loginHandler
}

var (
	_wireTokenGeneratorValue = handler.TokenGenerator(oauth2.GenerateToken)
)

func newLoginPasswordHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	validateProvider := webapp.ProvideValidateProvider(tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, provider, passwordProvider, oauthProvider, identityProvider)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, provider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	authorizationCodeStore := authn.ProvideAuthorizationCodeStore(context)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:                  authenticateProcess,
		Signup:                 signupProcess,
		AuthorizationCodeStore: authorizationCodeStore,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, provider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, provider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, provider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthUIProvider(providerFactory)
	stateStoreImpl := &webapp.StateStoreImpl{
		Context: context,
	}
	provider2 := sso.ProvideSSOProvider(context, tenantConfiguration)
	authenticateProviderImpl := &webapp.AuthenticateProviderImpl{
		ValidateProvider: validateProvider,
		RenderProvider:   renderProvider,
		AuthnProvider:    authnProvider,
		StateStore:       stateStoreImpl,
		SSOProvider:      provider2,
	}
	loginPasswordHandler := &LoginPasswordHandler{
		Provider: authenticateProviderImpl,
	}
	return loginPasswordHandler
}

func newForgotPasswordHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	forgotPasswordHandler := &ForgotPasswordHandler{
		RenderProvider: renderProvider,
	}
	return forgotPasswordHandler
}

func newSignupHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	validateProvider := webapp.ProvideValidateProvider(tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, provider, passwordProvider, oauthProvider, identityProvider)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, provider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	authorizationCodeStore := authn.ProvideAuthorizationCodeStore(context)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:                  authenticateProcess,
		Signup:                 signupProcess,
		AuthorizationCodeStore: authorizationCodeStore,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, provider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, provider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, provider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthUIProvider(providerFactory)
	stateStoreImpl := &webapp.StateStoreImpl{
		Context: context,
	}
	provider2 := sso.ProvideSSOProvider(context, tenantConfiguration)
	authenticateProviderImpl := &webapp.AuthenticateProviderImpl{
		ValidateProvider: validateProvider,
		RenderProvider:   renderProvider,
		AuthnProvider:    authnProvider,
		StateStore:       stateStoreImpl,
		SSOProvider:      provider2,
	}
	signupHandler := &SignupHandler{
		Provider: authenticateProviderImpl,
	}
	return signupHandler
}

func newSignupPasswordHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	validateProvider := webapp.ProvideValidateProvider(tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, provider, passwordProvider, oauthProvider, identityProvider)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, provider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	authorizationCodeStore := authn.ProvideAuthorizationCodeStore(context)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:                  authenticateProcess,
		Signup:                 signupProcess,
		AuthorizationCodeStore: authorizationCodeStore,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, provider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, provider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, provider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthUIProvider(providerFactory)
	stateStoreImpl := &webapp.StateStoreImpl{
		Context: context,
	}
	provider2 := sso.ProvideSSOProvider(context, tenantConfiguration)
	authenticateProviderImpl := &webapp.AuthenticateProviderImpl{
		ValidateProvider: validateProvider,
		RenderProvider:   renderProvider,
		AuthnProvider:    authnProvider,
		StateStore:       stateStoreImpl,
		SSOProvider:      provider2,
	}
	signupPasswordHandler := &SignupPasswordHandler{
		Provider: authenticateProviderImpl,
	}
	return signupPasswordHandler
}

func newSettingsHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	settingsHandler := &SettingsHandler{
		RenderProvider: renderProvider,
	}
	return settingsHandler
}

func newLogoutHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	manager := session.ProvideSessionManager(sessionStore, provider, tenantConfiguration, cookieConfiguration)
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	sessionManager := &oauth2.SessionManager{
		Store: grantStore,
		Time:  provider,
	}
	authSessionManager := &auth2.SessionManager{
		AuthInfoStore:       authinfoStore,
		UserProfileStore:    userprofileStore,
		IdentityProvider:    identityProvider,
		Hooks:               hookProvider,
		IDPSessions:         manager,
		AccessTokenSessions: sessionManager,
	}
	logoutHandler := &LogoutHandler{
		RenderProvider: renderProvider,
		SessionManager: authSessionManager,
	}
	return logoutHandler
}

func newSSOCallbackHandler(r *http.Request, m auth.DependencyMap) http.Handler {
	context := auth.ProvideContext(r)
	tenantConfiguration := auth.ProvideTenantConfig(context)
	validateProvider := webapp.ProvideValidateProvider(tenantConfiguration)
	engine := auth.ProvideTemplateEngine(tenantConfiguration, m)
	provider := time.NewProvider()
	sqlBuilderFactory := db.ProvideSQLBuilderFactory(tenantConfiguration)
	sqlBuilder := auth.ProvideAuthSQLBuilder(sqlBuilderFactory)
	sqlExecutor := db.ProvideSQLExecutor(context, tenantConfiguration)
	store := pq.ProvidePasswordHistoryStore(provider, sqlBuilder, sqlExecutor)
	passwordChecker := audit.ProvidePasswordChecker(tenantConfiguration, store)
	renderProvider := auth.ProvideWebAppRenderProvider(m, tenantConfiguration, engine, passwordChecker)
	requestID := auth.ProvideLoggingRequestID(r)
	factory := logging.ProvideLoggerFactory(context, requestID, tenantConfiguration)
	reservedNameChecker := auth.ProvideReservedNameChecker(m)
	passwordProvider := password.ProvidePasswordProvider(sqlBuilder, sqlExecutor, provider, store, factory, tenantConfiguration, reservedNameChecker)
	oauthProvider := oauth.ProvideOAuthProvider(sqlBuilder, sqlExecutor)
	v := auth.ProvidePrincipalProviders(oauthProvider, passwordProvider)
	identityProvider := principal.ProvideIdentityProvider(sqlBuilder, sqlExecutor, v)
	authenticateProcess := authn.ProvideAuthenticateProcess(factory, provider, passwordProvider, oauthProvider, identityProvider)
	loginIDChecker := loginid.ProvideLoginIDChecker(tenantConfiguration, reservedNameChecker)
	authinfoStore := pq2.ProvideStore(sqlBuilderFactory, sqlExecutor)
	userprofileStore := userprofile.ProvideStore(provider, sqlBuilder, sqlExecutor)
	txContext := db.ProvideTxContext(context, tenantConfiguration)
	hookProvider := hook.ProvideHookProvider(context, sqlBuilder, sqlExecutor, requestID, tenantConfiguration, txContext, provider, authinfoStore, userprofileStore, passwordProvider, factory)
	urlprefixProvider := urlprefix.NewProvider(r)
	executor := auth.ProvideTaskExecutor(m)
	queue := async.ProvideTaskQueue(context, txContext, requestID, tenantConfiguration, executor)
	signupProcess := authn.ProvideSignupProcess(passwordChecker, loginIDChecker, identityProvider, passwordProvider, oauthProvider, provider, authinfoStore, userprofileStore, hookProvider, tenantConfiguration, urlprefixProvider, queue)
	authorizationCodeStore := authn.ProvideAuthorizationCodeStore(context)
	oAuthCoordinator := &authn.OAuthCoordinator{
		Authn:                  authenticateProcess,
		Signup:                 signupProcess,
		AuthorizationCodeStore: authorizationCodeStore,
	}
	mfaStore := pq3.ProvideStore(tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	client := sms.ProvideSMSClient(context, tenantConfiguration)
	sender := mail.ProvideMailSender(context, tenantConfiguration)
	mfaSender := mfa.ProvideMFASender(tenantConfiguration, client, sender, engine)
	mfaProvider := mfa.ProvideMFAProvider(mfaStore, tenantConfiguration, provider, mfaSender)
	sessionStore := redis.ProvideStore(context, tenantConfiguration, provider, factory)
	eventStore := redis2.ProvideEventStore(context, tenantConfiguration)
	accessEventProvider := &auth2.AccessEventProvider{
		Store: eventStore,
	}
	sessionProvider := session.ProvideSessionProvider(r, sessionStore, accessEventProvider, tenantConfiguration)
	authorizationStore := &pq4.AuthorizationStore{
		SQLBuilder:  sqlBuilder,
		SQLExecutor: sqlExecutor,
	}
	grantStore := redis3.ProvideGrantStore(context, factory, tenantConfiguration, sqlBuilder, sqlExecutor, provider)
	authAccessEventProvider := auth2.AccessEventProvider{
		Store: eventStore,
	}
	idTokenIssuer := oidc.ProvideIDTokenIssuer(tenantConfiguration, urlprefixProvider, authinfoStore, userprofileStore, identityProvider, provider)
	tokenGenerator := _wireTokenGeneratorValue
	tokenHandler := handler.ProvideTokenHandler(r, tenantConfiguration, factory, authorizationStore, grantStore, grantStore, grantStore, authAccessEventProvider, sessionProvider, idTokenIssuer, tokenGenerator, provider)
	authnSessionProvider := authn.ProvideSessionProvider(mfaProvider, sessionProvider, tenantConfiguration, provider, authinfoStore, userprofileStore, identityProvider, hookProvider, tokenHandler)
	insecureCookieConfig := auth.ProvideSessionInsecureCookieConfig(m)
	cookieConfiguration := session.ProvideSessionCookieConfiguration(r, insecureCookieConfig, tenantConfiguration)
	mfaInsecureCookieConfig := auth.ProvideMFAInsecureCookieConfig(m)
	bearerTokenCookieConfiguration := mfa.ProvideBearerTokenCookieConfiguration(r, mfaInsecureCookieConfig, tenantConfiguration)
	providerFactory := &authn.ProviderFactory{
		OAuth:                   oAuthCoordinator,
		Authn:                   authenticateProcess,
		Signup:                  signupProcess,
		AuthnSession:            authnSessionProvider,
		Session:                 sessionProvider,
		SessionCookieConfig:     cookieConfiguration,
		BearerTokenCookieConfig: bearerTokenCookieConfiguration,
	}
	authnProvider := authn.ProvideAuthUIProvider(providerFactory)
	stateStoreImpl := &webapp.StateStoreImpl{
		Context: context,
	}
	provider2 := sso.ProvideSSOProvider(context, tenantConfiguration)
	authenticateProviderImpl := &webapp.AuthenticateProviderImpl{
		ValidateProvider: validateProvider,
		RenderProvider:   renderProvider,
		AuthnProvider:    authnProvider,
		StateStore:       stateStoreImpl,
		SSOProvider:      provider2,
	}
	loginIDNormalizerFactory := loginid.ProvideLoginIDNormalizerFactory(tenantConfiguration)
	redirectURLFunc := provideRedirectURIForWebAppFunc()
	oAuthProviderFactory := sso.ProvideOAuthProviderFactory(tenantConfiguration, urlprefixProvider, provider, loginIDNormalizerFactory, redirectURLFunc)
	oAuthProvider := provideOAuthProviderFromRequestVars(r, oAuthProviderFactory)
	ssoCallbackHandler := &SSOCallbackHandler{
		Provider:      authenticateProviderImpl,
		oauthProvider: oAuthProvider,
	}
	return ssoCallbackHandler
}

// wire.go:

var authDepSet = wire.NewSet(authn.ProvideAuthUIProvider, wire.Bind(new(webapp.AuthnProvider), new(*authn.Provider)), wire.Struct(new(webapp.AuthenticateProviderImpl), "*"))

func provideRedirectURIForWebAppFunc() sso.RedirectURLFunc {
	return redirectURIForWebApp
}

func provideOAuthProviderFromLoginForm(r *http.Request, spf *sso.OAuthProviderFactory) sso.OAuthProvider {
	idp := r.Form.Get("x_idp_id")
	return spf.NewOAuthProvider(idp)
}

func provideOAuthProviderFromRequestVars(r *http.Request, spf *sso.OAuthProviderFactory) sso.OAuthProvider {
	vars := mux.Vars(r)
	return spf.NewOAuthProvider(vars["provider"])
}
