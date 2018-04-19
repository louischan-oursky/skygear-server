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

package captcha

import (
	"fmt"

	tencentcaptcha "github.com/louischan-oursky/go-tencent-captcha"
)

// TencentProvider implements the Provider interface
type TencentProvider struct {
	AppID                 string
	AppSecretKey          string
	VerificationServerURL string
}

func (p *TencentProvider) Name() string {
	return "tencent"
}

func (p *TencentProvider) Verify(payload VerificationPayload) (bool, error) {
	ticket, ok := payload.Data["ticket"].(string)
	if !ok {
		return false, fmt.Errorf("expected `ticket` to be a string")
	}
	randstr, ok := payload.Data["randstr"].(string)
	if !ok {
		return false, fmt.Errorf("expected `randstr` to be a string")
	}
	fullTicket := tencentcaptcha.Ticket{
		Ticket:  ticket,
		Randstr: randstr,
		UserIP:  payload.RequestIP,
	}
	impl := tencentcaptcha.TencentCaptcha{
		AppID:                 p.AppID,
		AppSecretKey:          p.AppSecretKey,
		VerificationServerURL: p.VerificationServerURL,
	}
	result, err := impl.Verify(fullTicket)
	if err != nil {
		return false, err
	}
	if result.Success {
		return true, nil
	}
	return false, fmt.Errorf("tencent: %v", result.Error)
}
