// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import (
	"fmt"
	"strings"

	"github.com/luxfi/crypto/mldsa"
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

// CommitteeConfigMember is one signer in the genesis completion committee. Scheme
// is 1 (secp256k1) or 2 (ML-DSA-65); KeyID is a hex 20-byte id (the EVM address
// for secp256k1, an opaque fingerprint for ML-DSA-65); PubKey is the hex
// 1952-byte ML-DSA-65 public key (empty for secp256k1).
type CommitteeConfigMember struct {
	Scheme uint8  `json:"scheme"`
	Weight uint64 `json:"weight"`
	KeyID  string `json:"keyID"`
	PubKey string `json:"pubKey,omitempty"`
}

// Config carries the network-upgrade fields, the initial governance set (the
// registrar multisig), AND the initial bridge completion committee. The operators
// + threshold authorize registrar writes; the committee + quorum authorize bridge
// completions. Both are seeded at activation; tests may call SeedGovernance /
// SeedCommittee directly.
//
// Committee rotation is performed by a consensus/warp-attested path that writes a
// new epoch snapshot (out of scope here); the completion verifier is orthogonal —
// it only READS the current snapshot.
type Config struct {
	Upgrade   precompileconfig.Upgrade `json:"upgrade"`
	Operators []string                 `json:"operators,omitempty"` // hex-encoded addresses
	Threshold uint32                   `json:"threshold,omitempty"`

	CommitteeEpoch   uint64                  `json:"committeeEpoch,omitempty"`
	CommitteeQuorumN uint16                  `json:"committeeQuorumNum,omitempty"`
	CommitteeQuorumD uint16                  `json:"committeeQuorumDen,omitempty"`
	Committee        []CommitteeConfigMember `json:"committee,omitempty"`
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
	if c.CommitteeEpoch != other.CommitteeEpoch ||
		c.CommitteeQuorumN != other.CommitteeQuorumN ||
		c.CommitteeQuorumD != other.CommitteeQuorumD {
		return false
	}
	if len(c.Committee) != len(other.Committee) {
		return false
	}
	for i := range c.Committee {
		if c.Committee[i] != other.Committee[i] {
			return false
		}
	}
	return true
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	if err := c.verifyCommittee(); err != nil {
		return err
	}
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

// verifyCommittee validates the genesis committee config when present. An empty
// committee is permissibly absent (SeedCommittee may run later via an attested
// path); a present committee must parse to a valid, non-zero-weight set with a
// well-formed quorum fraction.
func (c *Config) verifyCommittee() error {
	if len(c.Committee) == 0 {
		return nil
	}
	_, err := parseCommittee(c.Committee)
	if err != nil {
		return err
	}
	if c.CommitteeQuorumN == 0 || c.CommitteeQuorumD == 0 || c.CommitteeQuorumN > c.CommitteeQuorumD {
		return fmt.Errorf("bridge: invalid committee quorum %d/%d", c.CommitteeQuorumN, c.CommitteeQuorumD)
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

	// Seed the bridge completion committee at the gateway address (mirrors
	// SeedGovernance for the registrar set). The committee is what the
	// completion verifier reads to authorize bridge-ins; without it every
	// completion fails closed with ErrCommitteeUnset.
	if len(c.Committee) > 0 {
		members, err := parseCommittee(c.Committee)
		if err != nil {
			return err
		}
		if err := SeedCommittee(
			state, BridgeGatewayCanonicalAddress,
			c.CommitteeEpoch, members, c.CommitteeQuorumN, c.CommitteeQuorumD,
		); err != nil {
			return err
		}
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

// parseCommittee decodes the genesis committee config into CommitteeMembers,
// validating the scheme and key material (a secp256k1 keyID is a 20-byte address;
// an ML-DSA-65 member carries the 1952-byte public key).
func parseCommittee(in []CommitteeConfigMember) ([]CommitteeMember, error) {
	out := make([]CommitteeMember, len(in))
	for i, m := range in {
		kid := common.FromHex(m.KeyID)
		if len(kid) != 20 {
			return nil, fmt.Errorf("bridge: committee member %d: keyID must be 20 bytes, got %d", i, len(kid))
		}
		cm := CommitteeMember{Scheme: byte(m.Scheme), Weight: m.Weight}
		copy(cm.KeyID[:], kid)
		switch cm.Scheme {
		case SchemeSecp256k1:
			if m.PubKey != "" {
				return nil, fmt.Errorf("bridge: committee member %d: secp256k1 carries no pubKey", i)
			}
		case SchemeMLDSA65:
			pk := common.FromHex(m.PubKey)
			if len(pk) != mldsa.MLDSA65PublicKeySize {
				return nil, fmt.Errorf("bridge: committee member %d: ML-DSA-65 pubKey must be %d bytes, got %d", i, mldsa.MLDSA65PublicKeySize, len(pk))
			}
			cm.PubKey = pk
		default:
			return nil, fmt.Errorf("bridge: committee member %d: unknown scheme %d", i, m.Scheme)
		}
		out[i] = cm
	}
	return out, nil
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
