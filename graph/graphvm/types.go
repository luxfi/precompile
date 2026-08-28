// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package graphvm provides types for GraphVM integration.
// This package implements the GraphQL query interface for graph databases.
package graphvm

import (
	"context"
	"maps"
	"slices"
	"strings"

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
	Variables     map[string]any
	OperationName string
}

// GraphQLResponse represents a GraphQL query response
type GraphQLResponse struct {
	Data   any
	Errors []GraphQLError
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message string
	Path    []string
}

// ResolverFunc is a function type for custom resolvers
type ResolverFunc func(ctx context.Context, db database.Database, args map[string]any) (any, error)

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
	data := make(map[string]any)

	// Check for custom resolvers first, in name order. The first match wins and returns,
	// so ranging the map directly made the winner depend on Go's randomised map iteration:
	// two registered resolvers both matching one query would resolve differently on
	// different validators, and this result is consensus output.
	for _, name := range slices.Sorted(maps.Keys(e.resolvers)) {
		if containsField(query, name) {
			result, err := e.resolvers[name](ctx, e.db, req.Variables)
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
		data["chainInfo"] = map[string]any{
			"vmName":   "graphvm",
			"version":  "1.0.0",
			"readOnly": true,
		}
	}
	if containsField(query, "balance") {
		data["balance"] = "0"
	}
	if containsField(query, "chains") {
		data["chains"] = []any{
			map[string]any{
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

// fieldDelimiters are the characters that may follow a field name in a query. Requiring one
// is what stops "chain" matching the field "chainInfo".
const fieldDelimiters = " {}()\n\t"

// containsField reports whether a GraphQL query names a field. It is a substring match, not
// a parse: the field must appear followed by a delimiter.
func containsField(query, field string) bool {
	if query == "" || field == "" {
		return false
	}
	for i := strings.Index(query, field); i >= 0; {
		rest := query[i+len(field):]
		if rest != "" && strings.ContainsAny(rest[:1], fieldDelimiters) {
			return true
		}
		next := strings.Index(query[i+1:], field)
		if next < 0 {
			return false
		}
		i += 1 + next
	}
	return false
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
