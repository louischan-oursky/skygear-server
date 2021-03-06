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

package skydb

import (
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"
)

func TestNewUserInfo(t *testing.T) {
	info := NewUserInfo("userinfoid", "john.doe@example.com", "secret")

	if info.Username != "userinfoid" {
		t.Fatalf("got info.ID = %v, want userinfoid", info.ID)
	}

	if info.Email != "john.doe@example.com" {
		t.Fatalf("got info.Email = %v, want john.doe@example.com", info.Email)
	}

	if bytes.Equal(info.HashedPassword, nil) {
		t.Fatalf("got info.HashPassword = %v, want non-empty value", info.HashedPassword)
	}
}

func TestNewUserInfoWithEmptyID(t *testing.T) {
	info := NewUserInfo("", "jane.doe@example.com", "anothersecret")

	if info.ID == "" {
		t.Fatalf("got empty info.ID, want non-empty string")
	}

	if info.Email != "jane.doe@example.com" {
		t.Fatalf("got info.Email = %v, want jane.doe@example.com", info.Email)
	}

	if bytes.Equal(info.HashedPassword, nil) {
		t.Fatalf("got info.HashPassword = %v, want non-empty value", info.HashedPassword)
	}
}

func TestNewAnonymousUserInfo(t *testing.T) {
	info := NewAnonymousUserInfo()
	if info.ID == "" {
		t.Fatalf("got info.ID = %v, want \"\"", info.ID)
	}

	if info.Email != "" {
		t.Fatalf("got info.Email = %v, want empty string", info.Email)
	}

	if len(info.HashedPassword) != 0 {
		t.Fatalf("got info.HashPassword = %v, want zero-length bytes", info.HashedPassword)
	}
}

func TestNewProvidedAuthUserInfo(t *testing.T) {
	k := "com.example:johndoe"
	v := map[string]interface{}{
		"hello": "world",
	}

	Convey("Test Provied Auth", t, func() {
		info := NewProvidedAuthUserInfo(k, v)
		So(info.Auth[k], ShouldResemble, v)
		So(len(info.HashedPassword), ShouldEqual, 0)
	})
}

func TestSetPassword(t *testing.T) {
	info := UserInfo{}
	info.SetPassword("secret")
	err := bcrypt.CompareHashAndPassword(info.HashedPassword, []byte("secret"))
	if err != nil {
		t.Fatalf("got err = %v, want nil", err)
	}
}

func TestIsSamePassword(t *testing.T) {
	info := UserInfo{}
	info.SetPassword("secret")
	if !info.IsSamePassword("secret") {
		t.Fatalf("got UserInfo.HashedPassword = %v, want a hashed \"secret\"", info.HashedPassword)
	}
}

func TestGetSetProvidedAuthData(t *testing.T) {
	Convey("Test Get/Set Provided Auth Data", t, func() {
		k := "com.example:johndoe"
		v := map[string]interface{}{
			"hello": "world",
		}

		Convey("Test Set Provided Auth", func() {
			info := UserInfo{}
			info.SetProvidedAuthData(k, v)

			So(info.Auth[k], ShouldResemble, v)
		})

		Convey("Test nonexistent Get Provided Auth", func() {
			info := UserInfo{
				Auth: AuthInfo{},
			}

			So(info.GetProvidedAuthData(k), ShouldBeNil)
		})

		Convey("Test Get Provided Auth", func() {
			info := UserInfo{
				Auth: AuthInfo(map[string]map[string]interface{}{
					k: v,
				}),
			}

			So(info.GetProvidedAuthData(k), ShouldResemble, v)
		})

		Convey("Test Remove Provided Auth", func() {
			info := UserInfo{
				Auth: AuthInfo(map[string]map[string]interface{}{
					k: v,
				}),
			}

			info.RemoveProvidedAuthData(k)
			v, _ = info.Auth[k]
			So(v, ShouldBeNil)
		})
	})
}
