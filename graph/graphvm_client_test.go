// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	gvm "github.com/luxfi/vm/vms/graphvm"
	"github.com/stretchr/testify/require"
)

func TestNewGraphVMClient(t *testing.T) {
	// Test with nil database
	t.Run("nil database", func(t *testing.T) {
		client := NewGraphVMClient(nil, nil)
		require.NotNil(t, client)
		require.Nil(t, client.executor)
		require.Equal(t, uint64(0), client.ChainID())
	})

	// Test with real database
	t.Run("with database", func(t *testing.T) {
		db := memdb.New()
		defer db.Close()

		client := NewGraphVMClient(db, nil)
		require.NotNil(t, client)
		require.NotNil(t, client.executor)
		require.Equal(t, uint64(0), client.ChainID())
	})

	// Test with chain ID
	t.Run("with chain ID", func(t *testing.T) {
		db := memdb.New()
		defer db.Close()

		client := NewGraphVMClientWithChainID(db, nil, 96369)
		require.NotNil(t, client)
		require.Equal(t, uint64(96369), client.ChainID())
	})
}

func TestGraphVMClientQuery(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	config := &gvm.GConfig{
		MaxQueryDepth:  10,
		MaxResultSize:  1 << 20,
		QueryTimeoutMs: 5000,
	}
	client := NewGraphVMClient(db, config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test chainInfo query
	t.Run("chainInfo query", func(t *testing.T) {
		result, err := client.Query(ctx, `query { chainInfo { vmName version readOnly } }`, nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		var data map[string]interface{}
		err = json.Unmarshal(result, &data)
		require.NoError(t, err)

		chainInfo, ok := data["chainInfo"].(map[string]interface{})
		require.True(t, ok, "expected chainInfo in response")
		require.Equal(t, "graphvm", chainInfo["vmName"])
		require.Equal(t, true, chainInfo["readOnly"])
	})

	// Test balance query (returns 0 for non-existent)
	t.Run("balance query", func(t *testing.T) {
		result, err := client.Query(ctx, `query { balance(address: "0x1234") }`, nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		var data map[string]interface{}
		err = json.Unmarshal(result, &data)
		require.NoError(t, err)
		require.Contains(t, data, "balance")
	})

	// Test chains query
	t.Run("chains query", func(t *testing.T) {
		result, err := client.Query(ctx, `query { chains { id name type } }`, nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		var data map[string]interface{}
		err = json.Unmarshal(result, &data)
		require.NoError(t, err)

		chains, ok := data["chains"].([]interface{})
		require.True(t, ok, "expected chains array")
		require.GreaterOrEqual(t, len(chains), 1)
	})

	// Test invalid query
	t.Run("invalid query", func(t *testing.T) {
		_, err := client.Query(ctx, `query { nonExistentField }`, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown field")
	})
}

func TestGraphVMClientQueryChain(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClientWithChainID(db, nil, 96369)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test query on same chain
	t.Run("same chain query", func(t *testing.T) {
		result, err := client.QueryChain(ctx, 96369, `query { chainInfo { vmName } }`, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	// Test query on local chain (chainID=0)
	t.Run("local chain query", func(t *testing.T) {
		result, err := client.QueryChain(ctx, 0, `query { chainInfo { vmName } }`, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	// Test cross-chain query (not yet supported)
	t.Run("cross-chain query", func(t *testing.T) {
		_, err := client.QueryChain(ctx, 200200, `query { chainInfo { vmName } }`, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cross-chain queries not yet supported")
	})
}

func TestGraphVMClientNilExecutor(t *testing.T) {
	client := NewGraphVMClient(nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query should fail gracefully
	_, err := client.Query(ctx, `query { chainInfo }`, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not initialized")

	// QueryChain should fail gracefully
	_, err = client.QueryChain(ctx, 0, `query { chainInfo }`, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not initialized")

	// GetDB should return nil
	require.Nil(t, client.GetDB())
}

func TestGraphVMClientGetDB(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)
	require.NotNil(t, client.GetDB())
	require.Equal(t, db, client.GetDB())
}

func TestGraphVMClientSetChainID(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)
	require.Equal(t, uint64(0), client.ChainID())

	client.SetChainID(96369)
	require.Equal(t, uint64(96369), client.ChainID())
}

func TestGraphVMClientRegisterResolver(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)

	// Register custom resolver
	customResolverCalled := false
	client.RegisterResolver("customQuery", func(ctx context.Context, db2 database.Database, args map[string]interface{}) (interface{}, error) {
		customResolverCalled = true
		return map[string]interface{}{"custom": "data"}, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query the custom resolver
	result, err := client.Query(ctx, `query { customQuery }`, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, customResolverCalled)
}
