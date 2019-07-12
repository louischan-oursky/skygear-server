package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/skygeario/skygear-server/pkg/auth"
	authTemplate "github.com/skygeario/skygear-server/pkg/auth/template"
	"github.com/skygeario/skygear-server/pkg/core/async"
	"github.com/skygeario/skygear-server/pkg/core/auth/authn/resolver"
	"github.com/skygeario/skygear-server/pkg/core/template"

	"github.com/kelseyhightower/envconfig"

	"github.com/joho/godotenv"
	"github.com/skygeario/skygear-server/pkg/auth/handler"
	forgotpwdhandler "github.com/skygeario/skygear-server/pkg/auth/handler/forgotpwd"
	ssohandler "github.com/skygeario/skygear-server/pkg/auth/handler/sso"
	userverifyhandler "github.com/skygeario/skygear-server/pkg/auth/handler/userverify"
	"github.com/skygeario/skygear-server/pkg/auth/task"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/core/middleware"
	"github.com/skygeario/skygear-server/pkg/core/server"
)

type configuration struct {
	Standalone                        bool
	StandaloneTenantConfigurationFile string `envconfig:"STANDALONE_TENANT_CONFIG_FILE" default:"standalone-tenant-config.yaml"`
	PathPrefix                        string `envconfig:"PATH_PREFIX"`
	Host                              string `default:"localhost:3000"`
}

func main() {
	envErr := godotenv.Load()
	if envErr != nil {
		log.Print("Error in loading .env file")
	}

	configuration := configuration{}
	envconfig.Process("", &configuration)

	// default template initialization
	templateEngine := template.NewEngine()
	authTemplate.RegisterDefaultTemplates(templateEngine)

	// logging initialization
	logging.SetModule("auth")

	asyncTaskExecutor := async.NewExecutor()
	authDependency := auth.DependencyMap{
		AsyncTaskExecutor: asyncTaskExecutor,
		TemplateEngine:    templateEngine,
	}

	task.AttachVerifyCodeSendTask(asyncTaskExecutor, authDependency)
	task.AttachPwHousekeeperTask(asyncTaskExecutor, authDependency)
	task.AttachWelcomeEmailSendTask(asyncTaskExecutor, authDependency)

	authContextResolverFactory := resolver.AuthContextResolverFactory{}

	var srv server.Server
	if configuration.Standalone {
		filename := configuration.StandaloneTenantConfigurationFile
		tenantConfig, err := config.NewTenantConfigurationFromYAMLAndEnv(func() (io.Reader, error) {
			return os.Open(filename)
		})
		if err != nil {
			log.Fatal(err)
		}

		serverOption := server.DefaultOption()
		serverOption.GearPathPrefix = configuration.PathPrefix
		srv = server.NewServerWithOption(configuration.Host, authContextResolverFactory, serverOption)
		srv.Use(middleware.TenantConfigurationMiddleware{
			ConfigurationProvider: middleware.ConfigurationProviderFunc(func(_ *http.Request) (config.TenantConfiguration, error) {
				return *tenantConfig, nil
			}),
		}.Handle)
	} else {
		srv = server.NewServer(configuration.Host, authContextResolverFactory)
	}

	srv.Use(middleware.RequestIDMiddleware{}.Handle)
	srv.Use(middleware.CORSMiddleware{}.Handle)

	handler.AttachSignupHandler(&srv, authDependency)
	handler.AttachLoginHandler(&srv, authDependency)
	handler.AttachLogoutHandler(&srv, authDependency)
	handler.AttachMeHandler(&srv, authDependency)
	handler.AttachSetDisableHandler(&srv, authDependency)
	handler.AttachChangePasswordHandler(&srv, authDependency)
	handler.AttachResetPasswordHandler(&srv, authDependency)
	handler.AttachWelcomeEmailHandler(&srv, authDependency)
	handler.AttachUpdateMetadataHandler(&srv, authDependency)
	forgotpwdhandler.AttachForgotPasswordHandler(&srv, authDependency)
	forgotpwdhandler.AttachForgotPasswordResetHandler(&srv, authDependency)
	userverifyhandler.AttachVerifyRequestHandler(&srv, authDependency)
	userverifyhandler.AttachVerifyCodeHandler(&srv, authDependency)
	ssohandler.AttachAuthURLHandler(&srv, authDependency)
	ssohandler.AttachConfigHandler(&srv, authDependency)
	ssohandler.AttachIFrameHandlerFactory(&srv, authDependency)
	ssohandler.AttachCustomTokenLoginHandler(&srv, authDependency)
	ssohandler.AttachAuthHandler(&srv, authDependency)
	ssohandler.AttachLoginHandler(&srv, authDependency)
	ssohandler.AttachLinkHandler(&srv, authDependency)
	ssohandler.AttachUnlinkHandler(&srv, authDependency)

	go func() {
		log.Printf("Auth gear boot")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// wait interrupt signal
	select {
	case <-sig:
		log.Printf("Stoping http server ...\n")
	}

	// create shutdown context with 10 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// shutdown the server
	err := srv.Shutdown(ctx)
	if err != nil {
		log.Printf("Shutdown request error: %v\n", err)
	}
}
