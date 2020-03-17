package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"

	"github.com/skygeario/skygear-server/pkg/auth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/loginid"
	"github.com/skygeario/skygear-server/pkg/auth/handler"
	forgotpwdhandler "github.com/skygeario/skygear-server/pkg/auth/handler/forgotpwd"
	gearHandler "github.com/skygeario/skygear-server/pkg/auth/handler/gear"
	loginidhandler "github.com/skygeario/skygear-server/pkg/auth/handler/loginid"
	mfaHandler "github.com/skygeario/skygear-server/pkg/auth/handler/mfa"
	"github.com/skygeario/skygear-server/pkg/auth/handler/session"
	ssohandler "github.com/skygeario/skygear-server/pkg/auth/handler/sso"
	userverifyhandler "github.com/skygeario/skygear-server/pkg/auth/handler/userverify"
	"github.com/skygeario/skygear-server/pkg/auth/task"
	"github.com/skygeario/skygear-server/pkg/core/async"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/middleware"
	"github.com/skygeario/skygear-server/pkg/core/redis"
	"github.com/skygeario/skygear-server/pkg/core/sentry"
	"github.com/skygeario/skygear-server/pkg/core/server"
	"github.com/skygeario/skygear-server/pkg/core/template"
	"github.com/skygeario/skygear-server/pkg/core/validation"
)

type configuration struct {
	Standalone                        bool
	StandaloneTenantConfigurationFile string                      `envconfig:"STANDALONE_TENANT_CONFIG_FILE" default:"standalone-tenant-config.yaml"`
	Host                              string                      `envconfig:"SERVER_HOST" default:"localhost:3000"`
	ValidHosts                        string                      `envconfig:"VALID_HOSTS"`
	Redis                             redis.Configuration         `envconfig:"REDIS"`
	UseInsecureCookie                 bool                        `envconfig:"INSECURE_COOKIE"`
	Template                          TemplateConfiguration       `envconfig:"TEMPLATE"`
	Default                           config.DefaultConfiguration `envconfig:"DEFAULT"`
	ReservedNameSourceFile            string                      `envconfig:"RESERVED_NAME_SOURCE_FILE" default:"reserved_name.txt"`
	// StaticAssetDir is for serving the static asset locally.
	// It should not be used for production.
	StaticAssetDir string `envconfig:"STATIC_ASSET_DIR"`
}

type TemplateConfiguration struct {
	EnableFileLoader   bool   `envconfig:"ENABLE_FILE_LOADER"`
	AssetGearEndpoint  string `envconfig:"ASSET_GEAR_ENDPOINT"`
	AssetGearMasterKey string `envconfig:"ASSET_GEAR_MASTER_KEY"`
}

/*
	@API Auth Gear
	@Version 1.0.0
	@Server {base_url}/_auth
		Auth Gear URL
		@Variable base_url https://my_app.skygearapis.com
			Skygear App URL

	@SecuritySchemeAPIKey access_key header X-Skygear-API-Key
		Access key used by client app
	@SecuritySchemeAPIKey master_key header X-Skygear-API-Key
		Master key used by admins, can perform administrative operations.
		Can be used as access key as well.
	@SecuritySchemeHTTP access_token Bearer token
		Access token of user
	@SecurityRequirement access_key

	@Tag User
		User information
	@Tag User Verification
		Login IDs verification
	@Tag Forgot Password
		Password recovery process
	@Tag Administration
		Administrative operation
	@Tag SSO
		Single sign-on
*/
func main() {
	// logging initialization
	logging.SetModule("auth")
	loggerFactory := logging.NewFactory(
		logging.NewDefaultLogHook(nil),
		&sentry.LogHook{Hub: sentry.DefaultClient.Hub},
	)
	logger := loggerFactory.NewLogger("auth")

	envErr := godotenv.Load()
	if envErr != nil {
		logger.WithError(envErr).Debug("Cannot load .env file")
	}

	configuration := configuration{}
	envconfig.Process("", &configuration)
	if configuration.ValidHosts == "" {
		configuration.ValidHosts = configuration.Host
	}

	validator := validation.NewValidator("http://v2.skgyear.io")
	validator.AddSchemaFragments(
		handler.ChangePasswordRequestSchema,
		handler.SetDisableRequestSchema,
		handler.RefreshRequestSchema,
		handler.ResetPasswordRequestSchema,
		handler.LoginRequestSchema,
		handler.SignupRequestSchema,
		handler.UpdateMetadataRequestSchema,

		forgotpwdhandler.ForgotPasswordRequestSchema,
		forgotpwdhandler.ForgotPasswordResetPageSchema,
		forgotpwdhandler.ForgotPasswordResetFormSchema,
		forgotpwdhandler.ForgotPasswordResetRequestSchema,

		mfaHandler.ActivateOOBRequestSchema,
		mfaHandler.ActivateTOTPRequestSchema,
		mfaHandler.AuthenticateBearerTokenRequestSchema,
		mfaHandler.AuthenticateOOBRequestSchema,
		mfaHandler.AuthenticateRecoveryCodeRequestSchema,
		mfaHandler.AuthenticateTOTPRequestSchema,
		mfaHandler.CreateOOBRequestSchema,
		mfaHandler.CreateTOTPRequestSchema,
		mfaHandler.DeleteAuthenticatorRequestSchema,
		mfaHandler.ListAuthenticatorRequestSchema,
		mfaHandler.TriggerOOBRequestSchema,

		session.GetRequestSchema,
		session.RevokeRequestSchema,

		ssohandler.AuthURLRequestSchema,
		ssohandler.LoginRequestSchema,
		ssohandler.LinkRequestSchema,
		ssohandler.AuthResultRequestSchema,

		userverifyhandler.VerifyCodeRequestSchema,
		userverifyhandler.VerifyRequestSchema,
		userverifyhandler.VerifyCodeFormSchema,
		userverifyhandler.UpdateVerifyStateRequestSchema,

		loginidhandler.AddLoginIDRequestSchema,
		loginidhandler.RemoveLoginIDRequestSchema,
		loginidhandler.UpdateLoginIDRequestSchema,
	)

	dbPool := db.NewPool()
	redisPool, err := redis.NewPool(configuration.Redis)
	if err != nil {
		logger.Fatalf("fail to create redis pool: %v", err.Error())
	}
	asyncTaskExecutor := async.NewExecutor(dbPool)
	var assetGearLoader *template.AssetGearLoader
	if configuration.Template.AssetGearEndpoint != "" && configuration.Template.AssetGearMasterKey != "" {
		assetGearLoader = &template.AssetGearLoader{
			AssetGearEndpoint:  configuration.Template.AssetGearEndpoint,
			AssetGearMasterKey: configuration.Template.AssetGearMasterKey,
		}
	}

	var reservedNameChecker *loginid.ReservedNameChecker
	reservedNameChecker, err = loginid.NewReservedNameChecker(configuration.ReservedNameSourceFile)
	if err != nil {
		logger.Fatalf("fail to load reserved name source file: %v", err.Error())
	}

	authDependency := auth.DependencyMap{
		EnableFileSystemTemplate: configuration.Template.EnableFileLoader,
		AssetGearLoader:          assetGearLoader,
		AsyncTaskExecutor:        asyncTaskExecutor,
		UseInsecureCookie:        configuration.UseInsecureCookie,
		DefaultConfiguration:     configuration.Default,
		Validator:                validator,
		ReservedNameChecker:      reservedNameChecker,
	}

	task.AttachVerifyCodeSendTask(asyncTaskExecutor, authDependency)
	task.AttachPwHousekeeperTask(asyncTaskExecutor, authDependency)
	task.AttachWelcomeEmailSendTask(asyncTaskExecutor, authDependency)

	var rootRouter *mux.Router
	var apiRouter *mux.Router
	if configuration.Standalone {
		filename := configuration.StandaloneTenantConfigurationFile
		reader, err := os.Open(filename)
		if err != nil {
			logger.WithError(err).Error("Cannot open standalone config")
		}
		tenantConfig, err := config.NewTenantConfigurationFromYAML(reader)
		if err != nil {
			logger.WithError(err).Fatal("Cannot parse standalone config")
		}

		rootRouter = server.NewRouter()
		rootRouter.Use(middleware.RequestIDMiddleware{}.Handle)
		rootRouter.Use(middleware.WriteTenantConfigMiddleware{
			ConfigurationProvider: middleware.ConfigurationProviderFunc(func(_ *http.Request) (config.TenantConfiguration, error) {
				return *tenantConfig, nil
			}),
		}.Handle)

		apiRouter = rootRouter.PathPrefix("/_auth").Subrouter()
		apiRouter.Use(middleware.ValidateHostMiddleware{ValidHosts: configuration.ValidHosts}.Handle)
		apiRouter.Use(middleware.CORSMiddleware{}.Handle)
	} else {
		rootRouter = server.NewRouter()
		rootRouter.Use(middleware.ReadTenantConfigMiddleware{}.Handle)

		apiRouter = rootRouter.PathPrefix("/_auth").Subrouter()
	}

	rootRouter.Use(middleware.DBMiddleware{Pool: dbPool}.Handle)
	rootRouter.Use(middleware.RedisMiddleware{Pool: redisPool}.Handle)

	apiRouter.Use(middleware.AuthMiddleware{}.Handle)
	apiRouter.Use(auth.MakeMiddleware(authDependency, auth.NewAccessKeyMiddleware))
	apiRouter.Use(middleware.Injecter{
		MiddlewareFactory: middleware.AuthnMiddlewareFactory{},
		Dependency:        authDependency,
	}.Handle)

	if configuration.StaticAssetDir != "" {
		rootRouter.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(configuration.StaticAssetDir))))
	}

	handler.AttachSignupHandler(apiRouter, authDependency)
	handler.AttachLoginHandler(apiRouter, authDependency)
	handler.AttachLogoutHandler(apiRouter, authDependency)
	handler.AttachRefreshHandler(apiRouter, authDependency)
	handler.AttachMeHandler(apiRouter, authDependency)
	handler.AttachSetDisableHandler(apiRouter, authDependency)
	handler.AttachChangePasswordHandler(apiRouter, authDependency)
	handler.AttachResetPasswordHandler(apiRouter, authDependency)
	handler.AttachUpdateMetadataHandler(apiRouter, authDependency)
	handler.AttachListIdentitiesHandler(apiRouter, authDependency)
	forgotpwdhandler.AttachForgotPasswordHandler(apiRouter, authDependency)
	forgotpwdhandler.AttachForgotPasswordResetHandler(apiRouter, authDependency)
	userverifyhandler.AttachVerifyRequestHandler(apiRouter, authDependency)
	userverifyhandler.AttachVerifyCodeHandler(apiRouter, authDependency)
	userverifyhandler.AttachUpdateHandler(apiRouter, authDependency)
	ssohandler.AttachAuthURLHandler(apiRouter, authDependency)
	ssohandler.AttachAuthRedirectHandler(apiRouter, authDependency)
	ssohandler.AttachAuthHandler(apiRouter, authDependency)
	ssohandler.AttachAuthResultHandler(apiRouter, authDependency)
	ssohandler.AttachLoginHandler(apiRouter, authDependency)
	ssohandler.AttachLinkHandler(apiRouter, authDependency)
	ssohandler.AttachUnlinkHandler(apiRouter, authDependency)
	session.AttachListHandler(apiRouter, authDependency)
	session.AttachGetHandler(apiRouter, authDependency)
	session.AttachRevokeHandler(apiRouter, authDependency)
	session.AttachRevokeAllHandler(apiRouter, authDependency)
	session.AttachResolveHandler(apiRouter, authDependency)
	mfaHandler.AttachListRecoveryCodeHandler(apiRouter, authDependency)
	mfaHandler.AttachRegenerateRecoveryCodeHandler(apiRouter, authDependency)
	mfaHandler.AttachListAuthenticatorHandler(apiRouter, authDependency)
	mfaHandler.AttachCreateTOTPHandler(apiRouter, authDependency)
	mfaHandler.AttachActivateTOTPHandler(apiRouter, authDependency)
	mfaHandler.AttachDeleteAuthenticatorHandler(apiRouter, authDependency)
	mfaHandler.AttachAuthenticateTOTPHandler(apiRouter, authDependency)
	mfaHandler.AttachRevokeAllBearerTokenHandler(apiRouter, authDependency)
	mfaHandler.AttachAuthenticateRecoveryCodeHandler(apiRouter, authDependency)
	mfaHandler.AttachAuthenticateBearerTokenHandler(apiRouter, authDependency)
	mfaHandler.AttachCreateOOBHandler(apiRouter, authDependency)
	mfaHandler.AttachTriggerOOBHandler(apiRouter, authDependency)
	mfaHandler.AttachActivateOOBHandler(apiRouter, authDependency)
	mfaHandler.AttachAuthenticateOOBHandler(apiRouter, authDependency)
	gearHandler.AttachTemplatesHandler(apiRouter, authDependency)
	loginidhandler.AttachAddLoginIDHandler(apiRouter, authDependency)
	loginidhandler.AttachRemoveLoginIDHandler(apiRouter, authDependency)
	loginidhandler.AttachUpdateLoginIDHandler(apiRouter, authDependency)

	srv := &http.Server{
		Addr:    configuration.Host,
		Handler: rootRouter,
	}
	server.ListenAndServe(srv, logger, "Starting auth gear")
}
