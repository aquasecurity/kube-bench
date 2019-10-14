// Copyright © 2017-2019 Aqua Security Software Ltd. <info@aquasec.com>
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

package cmd

import (
	"errors"
	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewRunFilter(t *testing.T) {

	type TestCase struct {
		Name       string
		FilterOpts FilterOpts
		Group      *check.Group
		Check      *check.Check

		Expected bool
	}

	testCases := []TestCase{
		{
			Name:       "Should return true when scored flag is enabled and check is scored",
			FilterOpts: FilterOpts{Scored: true, Unscored: false},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: true},
			Expected:   true,
		},
		{
			Name:       "Should return false when scored flag is enabled and check is not scored",
			FilterOpts: FilterOpts{Scored: true, Unscored: false},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: false},
			Expected:   false,
		},

		{
			Name:       "Should return true when unscored flag is enabled and check is not scored",
			FilterOpts: FilterOpts{Scored: false, Unscored: true},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: false},
			Expected:   true,
		},
		{
			Name:       "Should return false when unscored flag is enabled and check is scored",
			FilterOpts: FilterOpts{Scored: false, Unscored: true},
			Group:      &check.Group{},
			Check:      &check.Check{Scored: true},
			Expected:   false,
		},

		{
			Name:       "Should return true when group flag contains group's ID",
			FilterOpts: FilterOpts{Scored: true, Unscored: true, GroupList: "G1,G2,G3"},
			Group:      &check.Group{ID: "G2"},
			Check:      &check.Check{},
			Expected:   true,
		},
		{
			Name:       "Should return false when group flag doesn't contain group's ID",
			FilterOpts: FilterOpts{GroupList: "G1,G3"},
			Group:      &check.Group{ID: "G2"},
			Check:      &check.Check{},
			Expected:   false,
		},

		{
			Name:       "Should return true when check flag contains check's ID",
			FilterOpts: FilterOpts{Scored: true, Unscored: true, CheckList: "C1,C2,C3"},
			Group:      &check.Group{},
			Check:      &check.Check{ID: "C2"},
			Expected:   true,
		},
		{
			Name:       "Should return false when check flag doesn't contain check's ID",
			FilterOpts: FilterOpts{CheckList: "C1,C3"},
			Group:      &check.Group{},
			Check:      &check.Check{ID: "C2"},
			Expected:   false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			filter, _ := NewRunFilter(testCase.FilterOpts)
			assert.Equal(t, testCase.Expected, filter(testCase.Group, testCase.Check))
		})
	}

	t.Run("Should return error when both group and check flags are used", func(t *testing.T) {
		// given
		opts := FilterOpts{GroupList: "G1", CheckList: "C1"}
		// when
		_, err := NewRunFilter(opts)
		// then
		assert.EqualError(t, err, "group option and check option can't be used together")
	})

}

func TestIsMaster(t *testing.T) {
	t.Run("valid config, is master and all components are running", func(t *testing.T) {
		cfgFile = "../cfg/config.yaml"
		defer func() {
			cfgFile = ""
		}()
		initConfig()

		oldGetBinariesFunc := getBinariesFunc
		getBinariesFunc = func(viper *viper.Viper) (strings map[string]string, i error) {
			return map[string]string{"apiserver": "kube-apiserver"}, nil
		}
		defer func() {
			getBinariesFunc = oldGetBinariesFunc
		}()

		assert.True(t, isMaster())
	})

	t.Run("valid config, is master and but not all components are running", func(t *testing.T) {
		cfgFile = "../cfg/config.yaml"
		defer func() {
			cfgFile = ""
		}()
		initConfig()

		oldGetBinariesFunc := getBinariesFunc
		getBinariesFunc = func(viper *viper.Viper) (strings map[string]string, i error) {
			return map[string]string{}, nil
		}
		defer func() {
			getBinariesFunc = oldGetBinariesFunc
		}()

		assert.False(t, isMaster())
	})

	t.Run("valid config, is master, not all components are running and fails to find all binaries", func(t *testing.T) {
		cfgFile = "../cfg/config.yaml"
		defer func() {
			cfgFile = ""
		}()
		initConfig()

		oldGetBinariesFunc := getBinariesFunc
		getBinariesFunc = func(viper *viper.Viper) (strings map[string]string, i error) {
			return map[string]string{}, errors.New("failed to find binaries")
		}
		defer func() {
			getBinariesFunc = oldGetBinariesFunc
		}()

		assert.False(t, isMaster())
	})

	t.Run("valid config, does not include master", func(t *testing.T) {
		cfgFile = "../cfg/node_only.yaml"
		defer func() {
			cfgFile = ""
		}()
		initConfig()

		initConfig()
		assert.False(t, isMaster())
	})
}
