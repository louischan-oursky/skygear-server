package config

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/skygeario/skygear-server/pkg/gateway/model"
)

func TestStandaloneConfig(t *testing.T) {
	Convey("StandaloneConfig", t, func() {
		env := [][]string{
			{"STANDALONE_APP_NAME", "myapp"},
			{"STANDALONE_MASTER_KEY", "masterkey"},
			{"STANDALONE_DATABASE_URL", "postgres://"},
			{"STANDALONE_DEPLOYMENTROUTE_0_PATH", "/"},
			{"STANDALONE_DEPLOYMENTROUTE_0_BACKENDURL", "http://svc1:3000"},
			{"STANDALONE_DEPLOYMENTROUTE_1_PATH", "/api"},
			{"STANDALONE_DEPLOYMENTROUTE_1_BACKENDURL", "http://svc2:3000"},
		}
		defer func() {
			for _, pair := range env {
				_ = os.Unsetenv(pair[0])
			}
		}()
		for _, pair := range env {
			os.Setenv(pair[0], pair[1])
		}
		c := &Configuration{}
		err := c.ReadFromEnv()
		So(err, ShouldBeNil)
		So(c.Standalone.AppName, ShouldEqual, "myapp")
		So(c.Standalone.MasterKey, ShouldEqual, "masterkey")
		So(c.Standalone.DatabaseURL, ShouldEqual, "postgres://")
		So(c.Standalone.DeploymentRoutes, ShouldResemble, []*model.DeploymentRoute{
			&model.DeploymentRoute{
				Type: model.DeploymentRouteTypeHTTPService,
				Path: "/",
				TypeConfig: model.RouteTypeConfig{
					"backend_url": "http://svc1:3000",
				},
			},
			&model.DeploymentRoute{
				Type: model.DeploymentRouteTypeHTTPService,
				Path: "/api",
				TypeConfig: model.RouteTypeConfig{
					"backend_url": "http://svc2:3000",
				},
			},
		})
	})
}
