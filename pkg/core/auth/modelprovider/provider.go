package modelprovider

import (
	"github.com/skygeario/skygear-server/pkg/core/auth/model"
)

// Provider is a shorthand to generate model.
type Provider interface {
	GetUser(id string) (*model.User, error)
	GetIdentity(id string) (*model.Identity, error)
}
