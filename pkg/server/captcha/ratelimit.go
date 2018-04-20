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

// TokenBucketInfo represents a bucket used by TokenBucket.
type TokenBucketInfo struct {
	// Tokens is the number of remaining tokens in this bucket.
	// If the value is zero, then the limit is exceeded.
	Tokens float64
	// LastRequestedAt stores the last time this bucket has its
	// tokens decremented.
	// The algorithm uses this and a reference time to refill
	// tokens.
	LastRequestedAt time.Time
}

// TokenBucketStore contains storage operations required by TokenBucket.
type TokenBucketStore interface {
	// Get retrieves the info from the store.
	Get(id string) (TokenBucketInfo, bool, error)
	// Set saves the info to the store.
	Set(id string, info TokenBucketInfo) error
}

// TokenBucket implements the Token Bucket algorithm.
// Since it relies on two non-atomic storage operation,
// it suffers from data race.
// See https://en.wikipedia.org/wiki/Token_bucket
type TokenBucket struct {
	Store TokenBucketStore
	Rate  Rate
}

func (p *TokenBucket) Allow(id string) (bool, error) {
	return p.do(id, time.Now().UTC(), false)
}

func (p *TokenBucket) AllowAt(id string, t time.Time) (bool, error) {
	return p.do(id, t, false)
}

func (p *TokenBucket) IncrementAt(id string, t time.Time) (bool, error) {
	return p.do(id, t, true)
}

func (p *TokenBucket) Increment(id string) (bool, error) {
	return p.do(id, time.Now().UTC(), true)
}

func (p *TokenBucket) do(id string, t time.Time, set bool) (bool, error) {
	info, ok, err := p.Store.Get(id)
	if err != nil {
		return false, err
	}
	maxTokens := p.tokensFromRate()
	if !ok {
		// If the info is not found, we initialize a new one with
		// filled tokens.
		info = TokenBucketInfo{
			Tokens:          maxTokens,
			LastRequestedAt: t,
		}
	} else {
		// Otherwise we refill the tokens based on the difference between
		// t and LastRequestedAt
		tokensToRefill := p.tokensFromDiff(t, info.LastRequestedAt)
		tokens := info.Tokens
		tokens += tokensToRefill
		if tokens > maxTokens {
			tokens = maxTokens
		}
		info.Tokens = tokens
	}
	// Consume a token if possible
	ret := true
	if info.Tokens < 1.0 {
		ret = false
	} else {
		info.Tokens -= 1.0
	}
	info.LastRequestedAt = t
	if set {
		// Store the info
		err = p.Store.Set(id, info)
		if err != nil {
			return false, err
		}
	}
	return ret, nil
}

func (p *TokenBucket) tokensFromRate() float64 {
	return float64(p.Rate.Limit)
}

// Return how many tokens should be refilled per second
func (p *TokenBucket) refillRate() float64 {
	limit := float64(p.Rate.Limit)
	seconds := p.Rate.Duration.Seconds()
	if seconds == 0.0 {
		return 0.0
	}
	return limit / seconds
}

func (p *TokenBucket) tokensFromDiff(t time.Time, lastRequestedAt time.Time) float64 {
	// Ignore nonsense time
	if t.IsZero() || lastRequestedAt.IsZero() {
		return 0.0
	}
	duration := t.Sub(lastRequestedAt)
	// Ignore time traveler
	if duration < 0 {
		return 0.0
	}
	seconds := duration.Seconds()
	refillRate := p.refillRate()
	return refillRate * seconds
}
