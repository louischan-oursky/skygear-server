package sso

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/skygeario/skygear-server/pkg/core/config"
)

var (
	// BaseURLs is a map of provider base url
	BaseURLs = map[config.OAuthProviderType]string{
		config.OAuthProviderTypeGoogle:    "https://accounts.google.com/o/oauth2/v2/auth",
		config.OAuthProviderTypeFacebook:  "https://www.facebook.com/dialog/oauth",
		config.OAuthProviderTypeInstagram: "https://api.instagram.com/oauth/authorize",
		config.OAuthProviderTypeLinkedIn:  "https://www.linkedin.com/oauth/v2/authorization",
	}
	// AccessTokenURLs is a map of request access token url
	AccessTokenURLs = map[config.OAuthProviderType]string{
		config.OAuthProviderTypeGoogle:    "https://www.googleapis.com/oauth2/v4/token",
		config.OAuthProviderTypeFacebook:  "https://graph.facebook.com/v2.10/oauth/access_token",
		config.OAuthProviderTypeInstagram: "https://api.instagram.com/oauth/access_token",
		config.OAuthProviderTypeLinkedIn:  "https://www.linkedin.com/oauth/v2/accessToken",
	}
	// UserProfileURLs is a map of request ursr profile with access token
	UserProfileURLs = map[config.OAuthProviderType]string{
		config.OAuthProviderTypeGoogle:    "https://www.googleapis.com/oauth2/v1/userinfo",
		config.OAuthProviderTypeFacebook:  "https://graph.facebook.com/v2.10/me",
		config.OAuthProviderTypeInstagram: "https://api.instagram.com/v1/users/self",
		config.OAuthProviderTypeLinkedIn:  "https://www.linkedin.com/v1/people/~?format=json",
	}
)

// CustomClaims is the type for jwt encoded
type CustomClaims struct {
	State
	jwt.StandardClaims
}

// BaseURL returns base URL by provider name
func BaseURL(providerConfig config.OAuthProviderConfiguration) (u string) {
	u = BaseURLs[providerConfig.Type]
	return
}

// AccessTokenURL returns access token URL by provider name
func AccessTokenURL(providerConfig config.OAuthProviderConfiguration) (u string) {
	u = AccessTokenURLs[providerConfig.Type]
	return
}

// UserProfileURL returns user profile URL by provider name
func UserProfileURL(providerConfig config.OAuthProviderConfiguration) (u string) {
	u = UserProfileURLs[providerConfig.Type]
	return
}

// NewState constructs a new state
func NewState(params GetURLParams) State {
	return State{
		UXMode:      params.UXMode.String(),
		CallbackURL: params.CallbackURL,
		Action:      params.Action,
		UserID:      params.UserID,
	}
}

// EncodeState encodes state by JWT
func EncodeState(secret string, state State) (string, error) {
	claims := CustomClaims{
		state,
		jwt.StandardClaims{},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// DecodeState decodes state by JWT
func DecodeState(secret string, encoded string) (State, error) {
	claims := CustomClaims{}
	_, err := jwt.ParseWithClaims(encoded, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("fails to parse token")
		}
		return []byte(secret), nil
	})
	return claims.State, err
}

// RedirectURI generates redirect uri from URLPrefix and provider name
func RedirectURI(oauthConfig config.OAuthConfiguration, providerConfig config.OAuthProviderConfiguration) string {
	u, _ := url.Parse(oauthConfig.URLPrefix)
	orgPath := strings.TrimRight(u.Path, "/")
	path := fmt.Sprintf("%s/sso/%s/auth_handler", orgPath, providerConfig.ID)
	u.Path = path
	return u.String()
}
