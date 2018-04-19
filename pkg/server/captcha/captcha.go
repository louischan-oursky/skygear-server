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

// Service holds a provider. If the provider is nil,
// then captcha is disabled.
type Service struct {
	Provider Provider
}

// Provider represents a captcha service provider, e.g.
// reCAPTCHA by Google and Tencent Captcha by Tencent.
type Provider interface {
	// Name is the name of the captcha service provider, e.g.
	// "recaptcha" and "tencent"
	Name() string
	// Verify verifies whether the captcha challenge was
	// solved successfully. Depending on the underlying
	// service provider, this function may involve external
	// HTTP request to the service provider's server.
	// Tencent Captcha is one of such service provider.
	Verify(payload VerificationPayload) (bool, error)
}

type VerificationPayload struct {
	// Data contains the captcha challenge solution solved
	// by the client. It is expected that the client
	// conforms to the format implemented by the
	// providers.
	Data map[string]interface{}
	// The IP address of the HTTP request that submitted
	// the captcha challenge solution.
	RequestIP string
}
