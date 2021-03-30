// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/KennyChenFight/opa-envoy-amqp-plugin/internal/validator"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/KennyChenFight/opa-envoy-amqp-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/runtime"
)

func main() {
	runtime.RegisterPlugin("envoy.ext_authz.grpc", plugin.Factory{}) // for backwards compatibility
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})

	rego.RegisterBuiltin3(
		&rego.Function{
			Name:    "day_time_in_range",
			Decl:    types.NewFunction(types.Args(types.S, types.S, types.S), types.A),
			Memoize: true,
		},
		func(_ rego.BuiltinContext, a, b, c *ast.Term) (*ast.Term, error) {
			var headerStr string
			var startStr string
			var endStr string
			if err := ast.As(a.Value, &headerStr); err != nil {
				return nil, err
			} else if err := ast.As(b.Value, &startStr); err != nil {
				return nil, err
			} else if err := ast.As(c.Value, &endStr); err != nil {
				return nil, err
			}
			return ast.BooleanTerm(validator.ValidateDayTimeInRange(headerStr, startStr, endStr)), nil
		},
	)

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
