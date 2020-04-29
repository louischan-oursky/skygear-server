package flows

import (
	"errors"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity/oauth"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/interaction"
	"github.com/skygeario/skygear-server/pkg/auth/dependency/sso"
	"github.com/skygeario/skygear-server/pkg/auth/model"
	"github.com/skygeario/skygear-server/pkg/core/authn"
)

func (f *WebAppFlow) LoginWithOAuthProvider(oauthAuthInfo sso.AuthInfo) (*WebAppResult, error) {
	providerID := oauth.NewProviderID(oauthAuthInfo.ProviderConfig)
	claims := map[string]interface{}{
		interaction.IdentityClaimOAuthProvider:  providerID.ClaimsValue(),
		interaction.IdentityClaimOAuthSubjectID: oauthAuthInfo.ProviderUserInfo.ID,
		interaction.IdentityClaimOAuthProfile:   oauthAuthInfo.ProviderRawProfile,
		interaction.IdentityClaimOAuthClaims:    oauthAuthInfo.ProviderUserInfo.ClaimsValue(),
	}
	i, err := f.Interactions.NewInteractionLogin(&interaction.IntentLogin{
		Identity: interaction.IdentitySpec{
			Type:   authn.IdentityTypeOAuth,
			Claims: claims,
		},
	}, "")
	if err == nil {
		return f.afterPrimaryAuthentication(i)
	}
	if !errors.Is(err, interaction.ErrInvalidCredentials) {
		return nil, err
	}

	// try signup
	i, err = f.Interactions.NewInteractionSignup(&interaction.IntentSignup{
		Identity: interaction.IdentitySpec{
			Type:   authn.IdentityTypeOAuth,
			Claims: claims,
		},
		OnUserDuplicate: model.OnUserDuplicateAbort,
	}, "")
	if err != nil {
		return nil, err
	}
	s, err := f.Interactions.GetInteractionState(i)
	if err != nil {
		return nil, err
	}
	if s.CurrentStep().Step != interaction.StepCommit {
		panic("interaction_flow_webapp: unexpected interaction state")
	}
	_, err = f.Interactions.Commit(i)
	if err != nil {
		return nil, err
	}

	// create new interaction after signup
	i, err = f.Interactions.NewInteractionLogin(&interaction.IntentLogin{
		Identity: i.Identity.ToSpec(),
		AuthenticatedAs: &interaction.IntentLoginAuthenticatedAs{
			UserID: i.UserID,
		},
		OriginalIntentType: i.Intent.Type(),
	}, i.ClientID)
	if err != nil {
		return nil, err
	}
	return f.afterPrimaryAuthentication(i)
}