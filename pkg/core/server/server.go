package server

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/skygeario/skygear-server/pkg/core/inject"

	"github.com/skygeario/skygear-server/pkg/core/auth"
	"github.com/skygeario/skygear-server/pkg/core/db"
	"github.com/skygeario/skygear-server/pkg/core/middleware"

	"github.com/gorilla/mux"
	"github.com/skygeario/skygear-server/pkg/core/handler"
)

// SetupContextFunc setup context for usage in handler
type SetupContextFunc func(context.Context) context.Context

// CleanupContextFunc cleanup context after handler completed
type CleanupContextFunc func(context.Context)

// Server embeds a net/http server and has a gorillax mux internally
type Server struct {
	*http.Server

	router        *mux.Router
	dependencyMap inject.DependencyMap
}

// NewServer create a new Server with default option
func NewServer(
	addr string,
	dependencyMap inject.DependencyMap,
	dbPool db.Pool,
	setupCtxFn SetupContextFunc,
	cleanupCtxFn CleanupContextFunc,
) Server {
	return NewServerWithOption(
		addr,
		dependencyMap,
		dbPool,
		setupCtxFn,
		cleanupCtxFn,
		DefaultOption(),
	)
}

// NewServerWithOption create a new Server
func NewServerWithOption(
	addr string,
	dependencyMap inject.DependencyMap,
	dbPool db.Pool,
	setupCtxFn SetupContextFunc,
	cleanupCtxFn CleanupContextFunc,
	option Option,
) Server {
	router := mux.NewRouter()
	router.HandleFunc("/healthz", HealthCheckHandler)

	var subRouter *mux.Router
	if option.GearPathPrefix == "" {
		subRouter = router.NewRoute().Subrouter()
	} else {
		subRouter = router.PathPrefix(option.GearPathPrefix).Subrouter()
	}
	srv := Server{
		router: subRouter,
		Server: &http.Server{
			Addr:         addr,
			WriteTimeout: time.Second * 15,
			ReadTimeout:  time.Second * 15,
			IdleTimeout:  time.Second * 60,
			Handler:      router,
		},
		dependencyMap: dependencyMap,
	}

	if option.RecoverPanic {
		srv.Use(middleware.RecoverMiddleware{
			RecoverHandler: option.RecoverPanicHandler,
		}.Handle)
	}

	srv.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			r = auth.InitRequestAuthContext(r)
			r = db.InitRequestDBContext(r, dbPool)
			if setupCtxFn != nil {
				r = r.WithContext(setupCtxFn(r.Context()))
			}
			if cleanupCtxFn != nil {
				defer cleanupCtxFn(r.Context())
			}

			next.ServeHTTP(rw, r)
		})
	})

	return srv
}

// Handle delegates gorilla mux Handler, and accept a HandlerFactory instead of Handler
func (s *Server) Handle(path string, hf handler.Factory) *mux.Route {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := hf.NewHandler(r)
		h.ServeHTTP(w, r)
	})

	return s.router.NewRoute().Path(path).Handler(handler)
}

// Use set middlewares to underlying router
func (s *Server) Use(mwf ...mux.MiddlewareFunc) {
	s.router.Use(mwf...)
}

// HealthCheckHandler is basic handler for server health check
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "OK")
}
