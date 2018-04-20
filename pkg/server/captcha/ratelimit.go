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
	"time"
)

// Rate presents the rate.
// For example, Rate{Limit: 5, Duration: 5 * time.Minute} means
// 5 requests per 5 minutes.
type Rate struct {
	Limit    int64
	Duration time.Duration
}

// RateLimiter provides rate limiting.
// The id can be as simple as the IP address of the HTTP request,
// or a concatenation of the IP address and the URL path.
// An error is returned when the implementation's store
// encounters an I/O error.
type RateLimiter interface {
	// Allow is AllowAt(id, time.Now().UTC()).
	Allow(id string) (bool, error)

	// AllowAt determines whether the request identified by id received at t
	// is allowed to proceed.
	// It does not have side effects.
	AllowAt(id string, t time.Time) (bool, error)

	// Increment is IncrementAt(id, time.Now().UTC()).
	Increment(id string) (bool, error)
	// IncrementAt works like AllowAt but it also records the request, so it
	// has side effects.
	IncrementAt(id string, t time.Time) (bool, error)
}

// NoopRateLimiter does not impose any rate limit.
type NoopRateLimiter struct{}

func (r *NoopRateLimiter) Allow(id string) (bool, error) {
	return true, nil
}

func (r *NoopRateLimiter) AllowAt(id string, t time.Time) (bool, error) {
	return true, nil
}

func (r *NoopRateLimiter) Increment(id string) (bool, error) {
	return true, nil
}

func (r *NoopRateLimiter) IncrementAt(id string, t time.Time) (bool, error) {
	return true, nil
}
