package modelprovider

import (
	"github.com/skygeario/skygear-server/pkg/core/auth/authinfo"
	"github.com/skygeario/skygear-server/pkg/core/auth/model"
	"github.com/skygeario/skygear-server/pkg/core/auth/principal"
	"github.com/skygeario/skygear-server/pkg/core/auth/userprofile"
)

type ProviderImpl struct {
	AuthInfoStore    authinfo.Store
	UserProfileStore userprofile.Store
	IdentityProvider principal.IdentityProvider
}

func NewProvider(
	authInfoStore authinfo.Store,
	userProfileStore userprofile.Store,
	identityProvider principal.IdentityProvider,
) *ProviderImpl {
	return &ProviderImpl{
		AuthInfoStore:    authInfoStore,
		UserProfileStore: userProfileStore,
		IdentityProvider: identityProvider,
	}
}

func (p *ProviderImpl) GetUser(id string) (*model.User, error) {
	var authInfo authinfo.AuthInfo
	err := p.AuthInfoStore.GetAuth(id, &authInfo)
	if err != nil {
		return nil, err
	}
	userProfile, err := p.UserProfileStore.GetUserProfile(id)
	if err != nil {
		return nil, err
	}
	user := model.NewUser(authInfo, userProfile)
	return &user, nil
}

func (p *ProviderImpl) GetIdentity(id string) (*model.Identity, error) {
	prin, err := p.IdentityProvider.GetPrincipalByID(id)
	if err != nil {
		return nil, err
	}
	identity := model.NewIdentity(prin)
	return &identity, nil
}
