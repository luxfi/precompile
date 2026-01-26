// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package graphvm provides stub types for GraphVM integration.
// This package will be replaced by github.com/luxfi/vm/manager/graphvm
// once that package is implemented.
package graphvm

import (
	"context"

	"github.com/luxfi/database"
)

// GConfig holds GraphVM configuration
type GConfig struct {
	// MaxQueryDepth limits query nesting
	MaxQueryDepth int
	// MaxCacheSize limits cached entries
	MaxCacheSize int
	// QueryTimeout in seconds
	QueryTimeout int
	// MaxResultSize limits result size in bytes
	MaxResultSize int
	// QueryTimeoutMs is query timeout in milliseconds
	QueryTimeoutMs int
}

// GraphQLRequest represents a GraphQL query request
type GraphQLRequest struct {
	Query         string
	Variables     map[string]interface{}
	OperationName string
}

// GraphQLResponse represents a GraphQL query response
type GraphQLResponse struct {
	Data   interface{}
	Errors []GraphQLError
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message string
	Path    []string
}

// ResolverFunc is a function type for custom resolvers
type ResolverFunc func(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error)

// QueryExecutor executes GraphQL queries against the graph database
type QueryExecutor struct {
	db        database.Database
	config    *GConfig
	resolvers map[string]ResolverFunc
}

// NewQueryExecutor creates a new QueryExecutor
func NewQueryExecutor(db database.Database, config *GConfig) *QueryExecutor {
	return &QueryExecutor{
		db:        db,
		config:    config,
		resolvers: make(map[string]ResolverFunc),
	}
}

// Execute executes a GraphQL request and returns a response
func (e *QueryExecutor) Execute(ctx context.Context, req *GraphQLRequest) *GraphQLResponse {
	if e == nil || e.db == nil {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: "executor not initialized"}},
		}
	}

	// Mock implementation - parses query and returns appropriate mock data
	query := req.Query
	data := make(map[string]interface{})

	// Check for custom resolvers first
	for name, resolver := range e.resolvers {
		if containsField(query, name) {
			result, err := resolver(ctx, e.db, req.Variables)
			if err != nil {
				return &GraphQLResponse{
					Errors: []GraphQLError{{Message: err.Error()}},
				}
			}
			data[name] = result
			return &GraphQLResponse{Data: data}
		}
	}

	// Handle known mock queries
	if containsField(query, "chainInfo") {
		data["chainInfo"] = map[string]interface{}{
			"vmName":   "graphvm",
			"version":  "1.0.0",
			"readOnly": true,
		}
	}
	if containsField(query, "balance") {
		data["balance"] = "0"
	}
	if containsField(query, "chains") {
		data["chains"] = []interface{}{
			map[string]interface{}{
				"id":   "mainnet",
				"name": "Lux Mainnet",
				"type": "L1",
			},
		}
	}

	// Check for unknown fields
	if len(data) == 0 && !containsField(query, "chainInfo") && !containsField(query, "balance") && !containsField(query, "chains") {
		// Extract field name from query for error message
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: "unknown field in query"}},
		}
	}

	return &GraphQLResponse{
		Data:   data,
		Errors: nil,
	}
}

// containsField checks if a GraphQL query contains a specific field
func containsField(query, field string) bool {
	// Simple string match - real implementation would parse AST
	return len(query) > 0 && len(field) > 0 &&
		(contains(query, field+" ") || contains(query, field+"{") ||
		 contains(query, field+"(") || contains(query, field+"}") ||
		 contains(query, field+"\n") || contains(query, field+"\t"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// GetDB returns the underlying database
func (e *QueryExecutor) GetDB() database.Database {
	if e == nil {
		return nil
	}
	return e.db
}

// RegisterResolver adds a custom resolver
func (e *QueryExecutor) RegisterResolver(name string, resolver ResolverFunc) {
	if e == nil || e.resolvers == nil {
		return
	}
	e.resolvers[name] = resolver
}
