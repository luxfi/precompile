// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"

	"github.com/luxfi/ids"
)

// Context keys for consensus-related values
type contextKey string

const (
	chainIDKey contextKey = "chainID"
)

// GetChainID retrieves the chain ID from the context
func GetChainID(ctx context.Context) ids.ID {
	if v := ctx.Value(chainIDKey); v != nil {
		if chainID, ok := v.(ids.ID); ok {
			return chainID
		}
	}
	// Return empty ID if not found
	return ids.Empty
}

// WithChainID adds a chain ID to the context
func WithChainID(ctx context.Context, chainID ids.ID) context.Context {
	return context.WithValue(ctx, chainIDKey, chainID)
}
