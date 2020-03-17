package auth

import (
	"context"
	"net/http"

	"github.com/google/wire"
	"github.com/gorilla/mux"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/session"
	sessionredis "github.com/skygeario/skygear-server/pkg/auth/dependency/session/redis"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/webapp"
	"github.com/skygeario/skygear-server/pkg/auth/template"
	authinfopq "github.com/skygeario/skygear-server/pkg/core/auth/authinfo/pq"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/db"
	corehttp "github.com/skygeario/skygear-server/pkg/core/http"
	"github.com/skygeario/skygear-server/pkg/core/logging"
	coretemplate "github.com/skygeario/skygear-server/pkg/core/template"
	"github.com/skygeario/skygear-server/pkg/core/time"
)

func MakeHandler(deps DependencyMap, factory func(r *http.Request, m DependencyMap) http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := factory(r, deps)
		h.ServeHTTP(w, r)
	})
}

func MakeMiddleware(deps DependencyMap, factory func(r *http.Request, m DependencyMap) mux.MiddlewareFunc) mux.MiddlewareFunc {
	return mux.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := factory(r, deps)
			h := m(next)
			h.ServeHTTP(w, r)
		})
	})
}

func ProvideContext(r *http.Request) context.Context {
	return r.Context()
}

func ProvideTenantConfig(ctx context.Context) *config.TenantConfiguration {
	return config.GetTenantConfig(ctx)
}

func ProvideInsecureCookieConfig(m DependencyMap) session.InsecureCookieConfig {
	return session.InsecureCookieConfig(m.UseInsecureCookie)
}

func ProvideLoggingRequestID(r *http.Request) logging.RequestID {
	return logging.RequestID(r.Header.Get(corehttp.HeaderRequestID))
}

func ProvideAuthSQLBuilder(f db.SQLBuilderFactory) db.SQLBuilder {
	return f("auth")
}

// ProvideWebAppRenderProvider is placed here because it requires DependencyMap.
func ProvideWebAppRenderProvider(m DependencyMap, config *config.TenantConfiguration, templateEngine *coretemplate.Engine) webapp.RenderProvider {
	return &webapp.RenderProviderImpl{
		StaticAssetURLPrefix: m.StaticAssetURLPrefix,
		AuthConfiguration:    config.AppConfig.Auth,
		AuthUIConfiguration:  config.AppConfig.AuthUI,
		TemplateEngine:       templateEngine,
	}
}

func ProvideTemplateEngine(config *config.TenantConfiguration, m DependencyMap) *coretemplate.Engine {
	return template.NewEngineWithConfig(
		*config,
		m.EnableFileSystemTemplate,
		m.AssetGearLoader,
	)
}

var DependencySet = wire.NewSet(
	ProvideContext,
	ProvideTenantConfig,
	ProvideInsecureCookieConfig,
	ProvideTemplateEngine,
	ProvideWebAppRenderProvider,

	ProvideLoggingRequestID,
	ProvideAuthSQLBuilder,

	logging.DependencySet,
	time.DependencySet,
	db.DependencySet,
	authinfopq.DependencySet,
	session.DependencySet,
	sessionredis.DependencySet,
	webapp.DependencySet,
)
