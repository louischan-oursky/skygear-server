package userverify

import (
	"fmt"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/provider/password"
	"github.com/skygeario/skygear-server/pkg/core/auth/authinfo"
	"github.com/skygeario/skygear-server/pkg/core/config"
)

func IsUserVerified(
	authInfo *authinfo.AuthInfo,
	principals []*password.Principal,
	criteria config.UserVerificationCriteria,
	verifyConfigs map[string]config.UserVerificationKeyConfiguration,
) (verified bool) {
	verified = false
	if len(verifyConfigs) == 0 {
		return
	}

	switch criteria {
	case config.UserVerificationCriteriaAll:
		for _, principal := range principals {
			for key := range verifyConfigs {
				if principal.LoginIDKey != key {
					continue
				}
				if !authInfo.VerifyInfo[principal.LoginID] {
					verified = false
					return
				}
			}
		}
		verified = true

	case config.UserVerificationCriteriaAny:
		for _, principal := range principals {
			for key := range verifyConfigs {
				if principal.LoginIDKey != key {
					continue
				}
				if authInfo.VerifyInfo[principal.LoginID] {
					verified = true
					return
				}
			}
		}
		verified = false

	default:
		panic(fmt.Errorf("unexpected verify criteria `%s`", criteria))
	}
	return
}
