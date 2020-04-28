package flows

import (
	"github.com/skygeario/skygear-server/pkg/auth/dependency/interaction"
	"github.com/skygeario/skygear-server/pkg/auth/model"
	"github.com/skygeario/skygear-server/pkg/core/authn"
)

type WebAppFlow struct {
	Interactions   InteractionProvider
	UserController *UserController
}

func (f *WebAppFlow) LoginWithLoginID(loginID string) (*WebAppResult, error) {
	i, err := f.Interactions.NewInteractionLogin(&interaction.IntentLogin{
		Identity: interaction.IdentitySpec{
			Type: authn.IdentityTypeLoginID,
			Claims: map[string]interface{}{
				interaction.IdentityClaimLoginIDValue: loginID,
			},
		},
	}, "")
	if err != nil {
		return nil, err
	}

	s, err := f.Interactions.GetInteractionState(i)
	if err != nil {
		return nil, err
	} else if len(s.Steps) != 1 || s.Steps[0].Step != interaction.StepAuthenticatePrimary {
		panic("interaction_flow_webapp: unexpected interaction state")
	}

	token, err := f.Interactions.SaveInteraction(i)
	if err != nil {
		return nil, err
	}

	return &WebAppResult{
		Step:  WebAppStepAuthenticatePassword,
		Token: token,
	}, nil
}

func (f *WebAppFlow) SignupWithLoginID(loginIDKey, loginID string) (*WebAppResult, error) {
	i, err := f.Interactions.NewInteractionSignup(&interaction.IntentSignup{
		Identity: interaction.IdentitySpec{
			Type: authn.IdentityTypeLoginID,
			Claims: map[string]interface{}{
				interaction.IdentityClaimLoginIDKey:   loginIDKey,
				interaction.IdentityClaimLoginIDValue: loginID,
			},
		},
		OnUserDuplicate: model.OnUserDuplicateAbort,
	}, "")
	if err != nil {
		return nil, err
	}

	s, err := f.Interactions.GetInteractionState(i)
	if err != nil {
		return nil, err
	} else if len(s.Steps) != 1 || s.Steps[0].Step != interaction.StepSetupPrimaryAuthenticator {
		panic("interaction_flow_webapp: unexpected interaction state")
	}

	token, err := f.Interactions.SaveInteraction(i)
	if err != nil {
		return nil, err
	}

	return &WebAppResult{
		Step:  WebAppStepSetupPassword,
		Token: token,
	}, nil
}

func (f *WebAppFlow) AuthenticatePassword(token string, password string) (*WebAppResult, error) {
	i, err := f.Interactions.GetInteraction(token)
	if err != nil {
		return nil, err
	}

	err = f.Interactions.PerformAction(i, interaction.StepAuthenticatePrimary, &interaction.ActionAuthenticate{
		Authenticator: interaction.AuthenticatorSpec{Type: authn.AuthenticatorTypePassword},
		Secret:        password,
	})
	if err != nil {
		return nil, err
	}

	_, err = f.Interactions.SaveInteraction(i)
	if err != nil {
		return nil, err
	}

	if i.Error != nil {
		return nil, i.Error
	}

	return f.afterPrimaryAuthentication(i)
}

func (f *WebAppFlow) SetupPassword(token string, password string) (*WebAppResult, error) {
	i, err := f.Interactions.GetInteraction(token)
	if err != nil {
		return nil, err
	}

	err = f.Interactions.PerformAction(i, interaction.StepSetupPrimaryAuthenticator, &interaction.ActionSetupAuthenticator{
		Authenticator: interaction.AuthenticatorSpec{Type: authn.AuthenticatorTypePassword},
		Secret:        password,
	})
	if err != nil {
		return nil, err
	}

	_, err = f.Interactions.SaveInteraction(i)
	if err != nil {
		return nil, err
	}

	if i.Error != nil {
		return nil, i.Error
	}

	s, err := f.Interactions.GetInteractionState(i)
	if err != nil {
		return nil, err
	} else if s.CurrentStep().Step != interaction.StepCommit {
		panic("interaction_flow_webapp: unexpected interaction state")
	}

	attrs, err := f.Interactions.Commit(i)
	if err != nil {
		return nil, err
	}

	switch i.Intent.Type() {
	case interaction.IntentTypeSignup:
		// New interaction for logging in after signup
		i, err = f.Interactions.NewInteractionLoginAs(
			&interaction.IntentLogin{
				Identity: interaction.IdentitySpec{
					Type:   attrs.IdentityType,
					Claims: attrs.IdentityClaims,
				},
				OriginalIntentType: i.Intent.Type(),
			},
			attrs.UserID,
			i.Identity,
			i.PrimaryAuthenticator,
			i.ClientID,
		)
		if err != nil {
			return nil, err
		}

		// Primary authentication is done using `AuthenticatedAs`
		return f.afterPrimaryAuthentication(i)

	default:
		panic("interaction_flow_webapp: unexpected interaction intent")
	}
}

func (f *WebAppFlow) afterPrimaryAuthentication(i *interaction.Interaction) (*WebAppResult, error) {
	s, err := f.Interactions.GetInteractionState(i)
	if err != nil {
		return nil, err
	}
	switch s.CurrentStep().Step {
	case interaction.StepAuthenticateSecondary, interaction.StepSetupSecondaryAuthenticator:
		panic("interaction_flow_webapp: TODO: handle MFA")

	case interaction.StepCommit:
		attrs, err := f.Interactions.Commit(i)
		if err != nil {
			return nil, err
		}

		result, err := f.UserController.CreateSession(i, attrs, false)
		if err != nil {
			return nil, err
		}

		return &WebAppResult{
			Step:    WebAppStepCompleted,
			Cookies: result.Cookies,
		}, nil

	default:
		panic("interaction_flow_webapp: unexpected step " + s.CurrentStep().Step)
	}
}