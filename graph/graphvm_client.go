// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/luxfi/database"
	gvm "github.com/luxfi/vm/vms/graphvm"
)

// GraphVMClient implements GChainClient by wrapping a real gvm.QueryExecutor.
// This provides the bridge between the EVM precompile interface and the
// actual GraphVM query execution engine.
type GraphVMClient struct {
	executor *gvm.QueryExecutor
	chainID  uint64 // The chain ID this client is connected to
}

// Ensure GraphVMClient implements GChainClient
var _ GChainClient = (*GraphVMClient)(nil)

// NewGraphVMClient creates a new GraphVMClient wrapping a real QueryExecutor.
// If db is nil, a no-op client is returned that returns empty results.
func NewGraphVMClient(db database.Database, config *gvm.GConfig) *GraphVMClient {
	var executor *gvm.QueryExecutor
	if db != nil {
		executor = gvm.NewQueryExecutor(db, config)
	}
	return &GraphVMClient{
		executor: executor,
		chainID:  0, // Default to local/primary chain
	}
}

// NewGraphVMClientWithChainID creates a client for a specific chain ID.
func NewGraphVMClientWithChainID(db database.Database, config *gvm.GConfig, chainID uint64) *GraphVMClient {
	client := NewGraphVMClient(db, config)
	client.chainID = chainID
	return client
}

// Query executes a GraphQL query against the GraphVM.
// This is the main entry point for EVM contracts calling the precompile.
func (c *GraphVMClient) Query(ctx context.Context, query string, variables map[string]interface{}) ([]byte, error) {
	if c.executor == nil {
		return nil, fmt.Errorf("GraphVM client not initialized")
	}

	// Create GraphQL request
	req := &gvm.GraphQLRequest{
		Query:     query,
		Variables: variables,
	}

	// Execute against the real GraphVM
	resp := c.executor.Execute(ctx, req)

	// Check for errors
	if len(resp.Errors) > 0 {
		// Return first error as the main error
		errMsg := resp.Errors[0].Message
		for i := 1; i < len(resp.Errors); i++ {
			errMsg += "; " + resp.Errors[i].Message
		}
		return nil, fmt.Errorf("GraphQL error: %s", errMsg)
	}

	// Marshal the data response to JSON
	result, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return result, nil
}

// QueryChain executes a query against a specific chain.
// For the local GraphVM, this checks if chainID matches the connected chain.
// For cross-chain queries, this would route to the appropriate chain's GraphVM.
func (c *GraphVMClient) QueryChain(ctx context.Context, chainID uint64, query string, variables map[string]interface{}) ([]byte, error) {
	if c.executor == nil {
		return nil, fmt.Errorf("GraphVM client not initialized")
	}

	// For now, only support local chain queries
	// Cross-chain queries would require Warp messaging to route to other chains
	if chainID != 0 && chainID != c.chainID {
		return nil, fmt.Errorf("cross-chain queries not yet supported: requested chain %d, connected to %d", chainID, c.chainID)
	}

	// Execute the query locally
	return c.Query(ctx, query, variables)
}

// GetDB returns the underlying database for direct access if needed.
func (c *GraphVMClient) GetDB() database.Database {
	if c.executor == nil {
		return nil
	}
	return c.executor.GetDB()
}

// RegisterResolver allows adding custom resolvers to the GraphVM.
// This enables extending the GraphQL schema with precompile-specific queries.
func (c *GraphVMClient) RegisterResolver(name string, resolver gvm.ResolverFunc) {
	if c.executor != nil {
		c.executor.RegisterResolver(name, resolver)
	}
}

// ChainID returns the chain ID this client is connected to.
func (c *GraphVMClient) ChainID() uint64 {
	return c.chainID
}

// SetChainID updates the chain ID for this client.
func (c *GraphVMClient) SetChainID(chainID uint64) {
	c.chainID = chainID
}
