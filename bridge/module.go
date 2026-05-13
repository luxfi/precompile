// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"fmt"
	"strings"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// ConfigKey is the JSON key under which the registrar's config slots in.
const ConfigKey = "bridgeRegistrarConfig"

// Module registers the registrar precompile at 0x0446 so that
// modules.RegisteredModules() reports it.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractRegistrarAddress,
	Contract:     RegistrarPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

// Config carries the network-upgrade fields plus the initial governance set.
// The operators + threshold are required at activation — without them, every
// write call would revert with ErrUnauthorized. Tests that exercise the
// registrar in isolation should call SeedGovernance directly.
type Config struct {
	Upgrade   precompileconfig.Upgrade `json:"upgrade"`
	Operators []string                 `json:"operators,omitempty"` // hex-encoded addresses
	Threshold uint32                   `json:"threshold,omitempty"`
}

func (c *Config) Key() string {
	return ConfigKey
}

func (c *Config) Timestamp() *uint64 {
	return c.Upgrade.Timestamp()
}

func (c *Config) IsDisabled() bool {
	return c.Upgrade.Disable
}

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	if !c.Upgrade.Equal(&other.Upgrade) {
		return false
	}
	if c.Threshold != other.Threshold {
		return false
	}
	if len(c.Operators) != len(other.Operators) {
		return false
	}
	for i := range c.Operators {
		if c.Operators[i] != other.Operators[i] {
			return false
		}
	}
	return true
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	if len(c.Operators) == 0 && c.Threshold == 0 {
		return nil // permissibly empty; SeedGovernance must run later
	}
	if c.Threshold == 0 || int(c.Threshold) > len(c.Operators) {
		return fmt.Errorf(
			"registrar: invalid threshold %d for %d operators",
			c.Threshold, len(c.Operators),
		)
	}
	for _, op := range c.Operators {
		if _, err := parseAddress(op); err != nil {
			return err
		}
	}
	return nil
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

// Configure is called once when the upgrade activates. Seeds the operator
// set and threshold so subsequent write calls can be authorized.
func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	c, ok := cfg.(*Config)
	if !ok {
		// Empty config means no governance is seeded at activation. The
		// registrar is still registered; writes revert with ErrUnauthorized
		// until SeedGovernance is invoked.
		return nil
	}
	if len(c.Operators) == 0 || c.Threshold == 0 {
		return nil
	}
	ops, err := parseOperators(c.Operators)
	if err != nil {
		return err
	}
	return SeedGovernance(state, ops, c.Threshold)
}

func parseOperators(hexAddrs []string) ([]common.Address, error) {
	out := make([]common.Address, len(hexAddrs))
	for i, h := range hexAddrs {
		addr, err := parseAddress(h)
		if err != nil {
			return nil, err
		}
		out[i] = addr
	}
	return out, nil
}

func parseAddress(h string) (common.Address, error) {
	s := strings.TrimSpace(h)
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	if len(s) != 42 {
		return common.Address{}, fmt.Errorf("registrar: bad operator address %q", h)
	}
	return common.HexToAddress(s), nil
}
