package config

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"

	"github.com/skygeario/skygear-server/pkg/core/logging"
	"github.com/skygeario/skygear-server/pkg/gateway/model"
)

// Configuration is gateway startup configuration
type Configuration struct {
	Host          string        `envconfig:"HOST" default:"localhost:3001"`
	ConnectionStr string        `envconfig:"DATABASE_URL"`
	Auth          GearURLConfig `envconfig:"AUTH"`
	Standalone    StandaloneConfig
}

// ReadFromEnv reads from environment variable and update the configuration.
func (c *Configuration) ReadFromEnv() error {
	logger := logging.LoggerEntry("gateway")
	if err := godotenv.Load(); err != nil {
		logger.WithError(err).Info(
			"Error in loading .env file, continue without .env")
	}
	err := envconfig.Process("", c)
	if err != nil {
		return err
	}
	return c.Standalone.ReadDeploymentRoutes()
}

type StandaloneConfig struct {
	AppName          string `envconfig:"APP_NAME"`
	MasterKey        string `envconfig:"MASTER_KEY"`
	DatabaseURL      string `envconfig:"DATABASE_URL"`
	DeploymentRoutes []*model.DeploymentRoute
}

func (c *StandaloneConfig) ReadDeploymentRoutes() error {
	environ := os.Environ()
	m := map[int]*model.DeploymentRoute{}
	re, err := regexp.Compile(`^STANDALONE_DEPLOYMENTROUTE_(\d+)_(.+)$`)
	if err != nil {
		return err
	}
	for _, keyvalue := range environ {
		// Turn "a=b=c" into ["a", "b=c"]
		parts := strings.SplitN(keyvalue, "=", 2)
		key := parts[0]
		value := parts[1]
		matches := re.FindAllStringSubmatch(key, -1)
		// If match, matches is [["STANDALONE_DEPLOYMENTROUTE_0_PATH", "0", "PATH"]]
		if !(len(matches) == 1 && len(matches[0]) == 3) {
			continue
		}
		indexStr := matches[0][1]
		name := matches[0][2]
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			return err
		}
		if _, ok := m[index]; !ok {
			m[index] = &model.DeploymentRoute{
				Type: model.DeploymentRouteTypeHTTPService,
			}
		}
		switch name {
		case "PATH":
			m[index].Path = value
		case "BACKENDURL":
			m[index].TypeConfig = model.RouteTypeConfig{
				"backend_url": value,
			}
		}
	}
	c.DeploymentRoutes = make([]*model.DeploymentRoute, len(m))
	for i, route := range m {
		c.DeploymentRoutes[i] = route
	}
	return nil
}

type GearURLConfig struct {
	Live     string `envconfig:"LIVE_URL"`
	Previous string `envconfig:"PREVIOUS_URL"`
	Nightly  string `envconfig:"NIGHTLY_URL"`
}

// GetGearURL provide router map
func (c *Configuration) GetGearURL(gear model.Gear, version model.GearVersion) (string, error) {
	var g GearURLConfig
	switch gear {
	case model.AuthGear:
		g = c.Auth
	default:
		return "", errors.New("invalid gear")
	}

	switch version {
	case model.LiveVersion:
		return g.Live, nil
	case model.PreviousVersion:
		return g.Previous, nil
	case model.NightlyVersion:
		return g.Nightly, nil
	default:
		return "", errors.New("gear is suspended")
	}
}
