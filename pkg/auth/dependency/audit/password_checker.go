// Copyright 2015-present Oursky Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"regexp"
	"strings"

	"github.com/nbutton23/zxcvbn-go"

	"github.com/skygeario/skygear-server/pkg/auth/dependency/passwordhistory"
	corepassword "github.com/skygeario/skygear-server/pkg/core/password"
	"github.com/skygeario/skygear-server/pkg/core/skyerr"
)

func isUpperRune(r rune) bool {
	// NOTE: Intentionally not use unicode.IsUpper
	// because it take other languages into account.
	return r >= 'A' && r <= 'Z'
}

func isLowerRune(r rune) bool {
	// NOTE: Intentionally not use unicode.IsLower
	// because it take other languages into account.
	return r >= 'a' && r <= 'z'
}

func isDigitRune(r rune) bool {
	// NOTE: Intentionally not use unicode.IsDigit
	// because it take other languages into account.
	return r >= '0' && r <= '9'
}

func isSymbolRune(r rune) bool {
	// We define symbol as non-alphanumeric character
	return !isUpperRune(r) && !isLowerRune(r) && !isDigitRune(r)
}

func checkPasswordLength(password string, minLength int) bool {
	if minLength <= 0 {
		return true
	}
	// There exist many ways to define the length of a string
	// For example:
	// 1. The number of bytes of a given encoding
	// 2. The number of code points
	// 3. The number of extended grapheme cluster
	// Here we use the simpliest one:
	// the number of bytes of the given string in UTF-8 encoding
	return len(password) >= minLength
}

func checkPasswordUppercase(password string) bool {
	for _, r := range password {
		if isUpperRune(r) {
			return true
		}
	}
	return false
}

func checkPasswordLowercase(password string) bool {
	for _, r := range password {
		if isLowerRune(r) {
			return true
		}
	}
	return false
}

func checkPasswordDigit(password string) bool {
	for _, r := range password {
		if isDigitRune(r) {
			return true
		}
	}
	return false
}

func checkPasswordSymbol(password string) bool {
	for _, r := range password {
		if isSymbolRune(r) {
			return true
		}
	}
	return false
}

func checkPasswordExcludedKeywords(password string, keywords []string) bool {
	if len(keywords) <= 0 {
		return true
	}
	words := []string{}
	for _, w := range keywords {
		words = append(words, regexp.QuoteMeta(w))
	}
	re, err := regexp.Compile("(?i)" + strings.Join(words, "|"))
	if err != nil {
		return false
	}
	loc := re.FindStringIndex(password)
	if loc == nil {
		return true
	}
	return false
}

func checkPasswordGuessableLevel(password string, minLevel int, userInputs []string) (int, bool) {
	if minLevel <= 0 {
		return 0, true
	}
	minScore := minLevel - 1
	if minScore > 4 {
		minScore = 4
	}
	result := zxcvbn.PasswordStrength(password, userInputs)
	ok := result.Score >= minScore
	return result.Score + 1, ok
}

func userDataToStringStringMap(m map[string]interface{}) map[string]string {
	output := make(map[string]string)
	for key, value := range m {
		str, ok := value.(string)
		if ok {
			output[key] = str
		}
	}
	return output
}

func filterDictionary(m map[string]string, predicate func(string) bool) []string {
	output := []string{}
	for key, value := range m {
		ok := predicate(key)
		if ok {
			output = append(output, value)
		}
	}
	return output
}

func filterDictionaryByKeys(m map[string]string, keys []string) []string {
	lookupMap := make(map[string]bool)
	for _, key := range keys {
		lookupMap[key] = true
	}
	predicate := func(key string) bool {
		_, ok := lookupMap[key]
		return ok
	}

	return filterDictionary(m, predicate)
}

func filterDictionaryTakeAll(m map[string]string) []string {
	predicate := func(key string) bool {
		return true
	}
	return filterDictionary(m, predicate)
}

type ValidatePasswordPayload struct {
	AuthID        string
	PlainPassword string
	UserData      map[string]interface{}
}

type PasswordChecker struct {
	PwMinLength            int
	PwUppercaseRequired    bool
	PwLowercaseRequired    bool
	PwDigitRequired        bool
	PwSymbolRequired       bool
	PwMinGuessableLevel    int
	PwExcludedKeywords     []string
	PwExcludedFields       []string
	PwHistorySize          int
	PwHistoryDays          int
	PasswordHistoryEnabled bool
	PasswordHistoryStore   passwordhistory.Store
}

func (pc *PasswordChecker) policyPasswordLength() PasswordPolicy {
	return PasswordPolicy{
		Name: PasswordTooShort,
		Info: map[string]interface{}{
			"min_length": pc.PwMinLength,
		},
	}
}

func (pc *PasswordChecker) checkPasswordLength(password string) *PasswordPolicy {
	v := pc.policyPasswordLength()
	minLength := pc.PwMinLength
	if minLength > 0 && !checkPasswordLength(password, minLength) {
		v.Info["pw_length"] = len(password)
		return &v
	}
	return nil
}

func (pc *PasswordChecker) checkPasswordUppercase(password string) *PasswordPolicy {
	if pc.PwUppercaseRequired && !checkPasswordUppercase(password) {
		return &PasswordPolicy{Name: PasswordUppercaseRequired}
	}
	return nil
}

func (pc *PasswordChecker) checkPasswordLowercase(password string) *PasswordPolicy {
	if pc.PwLowercaseRequired && !checkPasswordLowercase(password) {
		return &PasswordPolicy{Name: PasswordLowercaseRequired}
	}
	return nil
}

func (pc *PasswordChecker) checkPasswordDigit(password string) *PasswordPolicy {
	if pc.PwDigitRequired && !checkPasswordDigit(password) {
		return &PasswordPolicy{Name: PasswordDigitRequired}
	}
	return nil
}

func (pc *PasswordChecker) checkPasswordSymbol(password string) *PasswordPolicy {
	if pc.PwSymbolRequired && !checkPasswordSymbol(password) {
		return &PasswordPolicy{Name: PasswordSymbolRequired}
	}
	return nil
}

func (pc *PasswordChecker) checkPasswordExcludedKeywords(password string) *PasswordPolicy {
	keywords := pc.PwExcludedKeywords
	if len(keywords) > 0 && !checkPasswordExcludedKeywords(password, keywords) {
		return &PasswordPolicy{Name: PasswordContainingExcludedKeywords}
	}
	return nil
}

func (pc *PasswordChecker) checkPasswordExcludedFields(password string, userData map[string]interface{}) *PasswordPolicy {
	fields := pc.PwExcludedFields
	if len(fields) > 0 {
		dict := userDataToStringStringMap(userData)
		keywords := filterDictionaryByKeys(dict, fields)
		if !checkPasswordExcludedKeywords(password, keywords) {
			return &PasswordPolicy{Name: PasswordContainingExcludedKeywords}
		}
	}
	return nil
}

func (pc *PasswordChecker) policyPasswordGuessableLevel() PasswordPolicy {
	return PasswordPolicy{
		Name: PasswordBelowGuessableLevel,
		Info: map[string]interface{}{
			"min_level": pc.PwMinGuessableLevel,
		},
	}
}

func (pc *PasswordChecker) checkPasswordGuessableLevel(password string, userData map[string]interface{}) *PasswordPolicy {
	v := pc.policyPasswordGuessableLevel()
	minLevel := pc.PwMinGuessableLevel
	if minLevel > 0 {
		dict := userDataToStringStringMap(userData)
		userInputs := filterDictionaryTakeAll(dict)
		level, ok := checkPasswordGuessableLevel(password, minLevel, userInputs)
		if !ok {
			v.Info["pw_level"] = level
			return &v
		}
	}
	return nil
}

func (pc *PasswordChecker) policyPasswordHistory() PasswordPolicy {
	return PasswordPolicy{
		Name: PasswordReused,
		Info: map[string]interface{}{
			"history_size": pc.PwHistorySize,
			"history_days": pc.PwHistoryDays,
		},
	}
}

func (pc *PasswordChecker) checkPasswordHistory(password, authID string) *PasswordPolicy {
	v := pc.policyPasswordHistory()
	if pc.shouldCheckPasswordHistory() && authID != "" {
		history, err := pc.PasswordHistoryStore.GetPasswordHistory(
			authID,
			pc.PwHistorySize,
			pc.PwHistoryDays,
		)
		if err != nil {
			return &v
		}
		for _, ph := range history {
			if IsSamePassword(ph.HashedPassword, password) {
				return &v
			}
		}
	}
	return nil
}

func (pc *PasswordChecker) ValidatePassword(payload ValidatePasswordPayload) error {
	password := payload.PlainPassword
	userData := payload.UserData
	authID := payload.AuthID

	var violations []skyerr.Cause
	check := func(v *PasswordPolicy) {
		if v != nil {
			violations = append(violations, *v)
		}
	}

	check(pc.checkPasswordLength(password))
	check(pc.checkPasswordUppercase(password))
	check(pc.checkPasswordLowercase(password))
	check(pc.checkPasswordDigit(password))
	check(pc.checkPasswordSymbol(password))
	check(pc.checkPasswordExcludedKeywords(password))
	check(pc.checkPasswordExcludedFields(password, userData))
	check(pc.checkPasswordGuessableLevel(password, userData))
	check(pc.checkPasswordHistory(password, authID))

	if len(violations) == 0 {
		return nil
	}

	return PasswordPolicyViolated.NewWithCauses("password policy violated", violations)
}

// PasswordPolicy outputs a list of PasswordPolicy to reflect the password policy.
func (pc *PasswordChecker) PasswordPolicy() (out []PasswordPolicy) {
	if pc.PwMinLength > 0 {
		out = append(out, pc.policyPasswordLength())
	}
	if pc.PwUppercaseRequired {
		out = append(out, PasswordPolicy{Name: PasswordUppercaseRequired})
	}
	if pc.PwLowercaseRequired {
		out = append(out, PasswordPolicy{Name: PasswordLowercaseRequired})
	}
	if pc.PwDigitRequired {
		out = append(out, PasswordPolicy{Name: PasswordDigitRequired})
	}
	if pc.PwSymbolRequired {
		out = append(out, PasswordPolicy{Name: PasswordSymbolRequired})
	}
	if len(pc.PwExcludedKeywords) > 0 {
		out = append(out, PasswordPolicy{Name: PasswordContainingExcludedKeywords})
	}
	if pc.PwMinGuessableLevel > 0 {
		out = append(out, pc.policyPasswordGuessableLevel())
	}
	if pc.shouldCheckPasswordHistory() {
		out = append(out, pc.policyPasswordHistory())
	}
	if out == nil {
		out = []PasswordPolicy{}
	}
	return
}

func (pc *PasswordChecker) ShouldSavePasswordHistory() bool {
	return pc.PasswordHistoryEnabled
}

func (pc *PasswordChecker) shouldCheckPasswordHistory() bool {
	return pc.ShouldSavePasswordHistory()
}

func IsSamePassword(hashedPassword []byte, password string) bool {
	return corepassword.Compare([]byte(password), hashedPassword) == nil
}
