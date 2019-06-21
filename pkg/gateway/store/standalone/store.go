package standalone

import (
	"github.com/skygeario/skygear-server/pkg/core/config"
	gatewayConfig "github.com/skygeario/skygear-server/pkg/gateway/config"
	"github.com/skygeario/skygear-server/pkg/gateway/model"
	"github.com/skygeario/skygear-server/pkg/gateway/store"
)

type Store struct {
	Standalone gatewayConfig.StandaloneConfig
}

func (s *Store) GetAppByDomain(domain string, app *model.App) error {
	app.ID = "standalone"
	app.Name = "standalone"
	tenantConfig := config.TenantConfiguration{
		AppName:         s.Standalone.AppName,
		MasterKey:       s.Standalone.MasterKey,
		DBConnectionStr: s.Standalone.DatabaseURL,
	}
	tenantConfig.AfterUnmarshal()
	app.Config = tenantConfig
	app.Plan = model.Plan{
		AuthEnabled: true,
	}
	app.AuthVersion = model.LiveVersion
	return nil
}

func (s *Store) GetLastDeploymentRoutes(app model.App) ([]*model.DeploymentRoute, error) {
	return s.Standalone.DeploymentRoutes, nil
}

func (s *Store) Close() error {
	return nil
}

var (
	_ store.GatewayStore = &Store{}
)
