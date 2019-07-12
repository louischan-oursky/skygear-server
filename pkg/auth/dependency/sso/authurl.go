package sso

import (
	"fmt"
	"net/url"

	"github.com/skygeario/skygear-server/pkg/core/config"
)

type authURLParams struct {
	oauthConfig    config.OAuthConfiguration
	providerConfig config.OAuthProviderConfiguration
	options        Options
	state          State
	baseURL        string
}

func authURL(params authURLParams) (string, error) {
	encodedState, err := EncodeState(params.oauthConfig.StateJWTSecret, params.state)
	if err != nil {
		return "", err
	}
	v := url.Values{}
	v.Set("response_type", "code")
	v.Add("client_id", params.providerConfig.ClientID)
	v.Add("redirect_uri", RedirectURI(params.oauthConfig, params.providerConfig))
	v.Add("state", encodedState)
	v.Add("scope", params.providerConfig.Scope)
	for k, o := range params.options {
		v.Add(k, fmt.Sprintf("%v", o))
	}
	return params.baseURL + "?" + v.Encode(), nil
}
