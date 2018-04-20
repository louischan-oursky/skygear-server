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
	"testing"
	"time"
)

func TestNoopRateLimiter(t *testing.T) {
	noop := NoopRateLimiter{}
	var rateLimiter RateLimiter
	// Ensure it implements RateLimiter
	rateLimiter = &noop
	b1, err := rateLimiter.Allow("id")
	if !b1 || err != nil {
		t.Fail()
	}
	b2, err := rateLimiter.AllowAt("id", time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC))
	if !b2 || err != nil {
		t.Fail()
	}
	b3, err := rateLimiter.Increment("id")
	if !b3 || err != nil {
		t.Fail()
	}
	b4, err := rateLimiter.IncrementAt("id", time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC))
	if !b4 || err != nil {
		t.Fail()
	}
}
