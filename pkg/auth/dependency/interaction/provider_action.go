package interaction

import (
	"errors"
	"fmt"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/identity"
	"github.com/skygeario/skygear-server/pkg/core/skyerr"
)

func (p *Provider) PerformAction(i *Interaction, step Step, action Action) error {
	state, err := p.GetInteractionState(i)
	if err != nil {
		return err
	}

	var stepState *StepState
	for _, s := range state.Steps {
		if s.Step == step {
			stepState = &s
			break
		}
	}
	if stepState == nil {
		return ErrInvalidStep
	}

	switch intent := i.Intent.(type) {
	case *IntentLogin:
		return p.performActionLogin(i, intent, stepState, state, action)
	case *IntentSignup:
		return p.performActionSignup(i, intent, stepState, state, action)
	}
	panic(fmt.Sprintf("interaction: unknown intent type %T", i.Intent))
}

func (p *Provider) performActionLogin(i *Interaction, intent *IntentLogin, step *StepState, s *State, action Action) error {
	switch step.Step {
	case StepAuthenticatePrimary, StepAuthenticateSecondary:
		switch action := action.(type) {
		case *ActionAuthenticate:
			authen, err := p.doAuthenticate(i, step, &i.State, intent.Identity, action.Authenticator, action.Secret)
			if skyerr.IsAPIError(err) {
				i.Error = skyerr.AsAPIError(err)
				return nil
			} else if err != nil {
				return err
			}

			ar := authen.ToRef()
			if step.Step == StepAuthenticatePrimary {
				i.PrimaryAuthenticator = &ar
				i.SecondaryAuthenticator = nil
			} else {
				i.SecondaryAuthenticator = &ar
			}
			i.Error = nil
			return nil

		case *ActionTriggerOOBAuthenticator:
			err := p.doTriggerOOB(i, action)
			if err != nil {
				return err
			}
			return nil
		default:
			panic(fmt.Sprintf("interaction_login: unhandled authenticate action %T", action))
		}

	case StepSetupSecondaryAuthenticator:
		// TODO(interaction): setup secondary authenticator

	case StepCommit:
		// TODO(interaction): allow setup bearer token

	}
	panic("interaction_login: unhandled step " + step.Step)
}

func (p *Provider) performActionSignup(i *Interaction, intent *IntentSignup, step *StepState, s *State, action Action) error {
	switch step.Step {
	case StepSetupPrimaryAuthenticator:
		switch action := action.(type) {
		case *ActionSetupAuthenticator:
			authen, err := p.setupAuthenticator(i, step, &i.State, action.Authenticator, action.Secret)
			if skyerr.IsAPIError(err) {
				i.Error = skyerr.AsAPIError(err)
				return nil
			} else if err != nil {
				return err
			}

			ar := authen.ToRef()
			i.PrimaryAuthenticator = &ar
			i.Error = nil
			return nil

		case *ActionTriggerOOBAuthenticator:
			// TODO(interaction): handle OOB trigger
		default:
			panic(fmt.Sprintf("interaction_signup: unhandled authenticate action %T", action))
		}

	}
	panic("interaction_signup: unhandled step " + step.Step)
}

func (p *Provider) doAuthenticate(i *Interaction, step *StepState, astate *map[string]string, is IdentitySpec, as AuthenticatorSpec, secret string) (*AuthenticatorInfo, error) {
	userID, iden, err := p.Identity.GetByClaims(is.Type, is.Claims)
	if errors.Is(err, identity.ErrIdentityNotFound) {
		return nil, ErrInvalidCredentials
	} else if err != nil {
		return nil, err
	}

	authen, err := p.Authenticator.Authenticate(userID, as, astate, secret)
	if err != nil {
		return nil, err
	}

	i.UserID = userID
	ir := iden.ToRef()
	i.Identity = &ir
	i.State = nil
	return authen, nil
}

func (p *Provider) setupAuthenticator(i *Interaction, step *StepState, astate *map[string]string, as AuthenticatorSpec, secret string) (*AuthenticatorInfo, error) {
	ok := false
	for _, aa := range step.AvailableAuthenticators {
		if aa.Type == as.Type {
			ok = true
			break
		}
	}
	if !ok {
		// Authenticator is not available for current step, reject it
		return nil, ErrInvalidAction
	}

	// TODO(interaction): special handling for OTP
	ais, err := p.Authenticator.New(i.UserID, as, secret)
	if err != nil {
		return nil, err
	}
	i.NewAuthenticators = append(i.NewAuthenticators, ais...)
	i.State = nil
	return ais[0], nil
}

func (p *Provider) doTriggerOOB(i *Interaction, action *ActionTriggerOOBAuthenticator) (err error) {
	spec := action.Authenticator

	if spec.ID == "" {
		panic("expected ActionTriggerOOBAuthenticator.Authenticator.ID to be present")
	}

	if spec.Type != AuthenticatorTypeOOBOTP {
		panic("unexpected ActionTriggerOOBAuthenticator.Authenticator.Type: " + spec.Type)
	}

	now := p.Time.NowUTC()
	triggerTime, err := now.MarshalText()
	if err != nil {
		return
	}

	if i.State == nil {
		i.State = map[string]string{}
	}

	// Check if the authenticator has been changed or unset at all.
	// If authenticator changes, generate a new code.
	id := i.State[AuthenticatorStateOOBOTPID]
	if id != spec.ID {
		id = spec.ID
		delete(i.State, AuthenticatorStateOOBOTPCode)
	}

	// Check if we have a code already.
	code := i.State[AuthenticatorStateOOBOTPCode]
	if code == "" {
		code = p.OOB.GenerateCode()
	}

	err = p.OOB.SendCode(spec, code)
	if err != nil {
		return
	}

	// Perform mutation on interaction at the end.
	i.State[AuthenticatorStateOOBOTPID] = id
	i.State[AuthenticatorStateOOBOTPCode] = code
	i.State[AuthenticatorStateOOBOTPTriggerTime] = string(triggerTime)

	return
}