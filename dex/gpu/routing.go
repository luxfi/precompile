// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"container/heap"
	"errors"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
)

// =============================================================================
// Graph-Based Route Optimization
// =============================================================================

// PoolGraph represents the DEX as a graph for pathfinding.
// Nodes are tokens, edges are pools.
type PoolGraph struct {
	mu sync.RWMutex

	// Token ID -> list of connected pools
	adjacency map[[20]byte][]PoolEdge

	// Pool ID -> pool data
	pools map[[32]byte]*PoolData

	// Cache for frequently used routes
	routeCache map[routeCacheKey]*CachedRoute
	cacheHits  uint64
	cacheMiss  uint64
}

// PoolEdge represents a pool connecting two tokens.
type PoolEdge struct {
	PoolID       [32]byte
	Token0       [20]byte
	Token1       [20]byte
	Fee          uint32
	Liquidity    Liquidity128
	SqrtPriceX96 SqrtPriceX96
	Tick         int32
	LastUpdate   uint64 // Block number
}

// PoolData holds pool state for routing.
type PoolData struct {
	SqrtPriceX96 SqrtPriceX96
	Liquidity    Liquidity128
	Tick         int32
	Fee          uint32
	Token0       [20]byte
	Token1       [20]byte
}

// routeCacheKey is the key for route caching.
type routeCacheKey struct {
	TokenIn   [20]byte
	TokenOut  [20]byte
	AmountIn  uint64 // Quantized amount for cache key
}

// CachedRoute holds a cached optimal route.
type CachedRoute struct {
	Route      []PoolEdge
	AmountOut  *big.Int
	ValidUntil uint64 // Block number
}

// NewPoolGraph creates a new pool graph.
func NewPoolGraph() *PoolGraph {
	return &PoolGraph{
		adjacency:  make(map[[20]byte][]PoolEdge),
		pools:      make(map[[32]byte]*PoolData),
		routeCache: make(map[routeCacheKey]*CachedRoute),
	}
}

// AddPool adds or updates a pool in the graph.
func (g *PoolGraph) AddPool(poolID [32]byte, data *PoolData) {
	g.mu.Lock()
	defer g.mu.Unlock()

	edge := PoolEdge{
		PoolID:       poolID,
		Token0:       data.Token0,
		Token1:       data.Token1,
		Fee:          data.Fee,
		Liquidity:    data.Liquidity,
		SqrtPriceX96: data.SqrtPriceX96,
		Tick:         data.Tick,
	}

	// Add edge in both directions
	g.adjacency[data.Token0] = append(g.adjacency[data.Token0], edge)
	g.adjacency[data.Token1] = append(g.adjacency[data.Token1], edge)
	g.pools[poolID] = data
}

// UpdatePool updates pool state.
func (g *PoolGraph) UpdatePool(poolID [32]byte, sqrtPrice SqrtPriceX96, liquidity Liquidity128, tick int32) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if pool, ok := g.pools[poolID]; ok {
		pool.SqrtPriceX96 = sqrtPrice
		pool.Liquidity = liquidity
		pool.Tick = tick

		// Update edges
		for _, token := range [][20]byte{pool.Token0, pool.Token1} {
			edges := g.adjacency[token]
			for i := range edges {
				if edges[i].PoolID == poolID {
					edges[i].SqrtPriceX96 = sqrtPrice
					edges[i].Liquidity = liquidity
					edges[i].Tick = tick
				}
			}
		}
	}
}

// =============================================================================
// Dijkstra-Based Optimal Route Finding
// =============================================================================

// routeNode represents a node in the routing priority queue.
type routeNode struct {
	token     [20]byte
	amountOut *big.Int     // Current amount at this node
	gasUsed   uint64
	path      []PoolEdge   // Path taken to reach here
	index     int          // Heap index
}

// routeHeap implements heap.Interface for A* routing.
type routeHeap []*routeNode

func (h routeHeap) Len() int { return len(h) }

func (h routeHeap) Less(i, j int) bool {
	// Prefer higher output (we're maximizing)
	return h[i].amountOut.Cmp(h[j].amountOut) > 0
}

func (h routeHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *routeHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*routeNode)
	item.index = n
	*h = append(*h, item)
}

func (h *routeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[0 : n-1]
	return item
}

// FindOptimalRoute finds the best route using Dijkstra's algorithm.
// Returns the route with maximum output for given input.
func (g *PoolGraph) FindOptimalRoute(
	tokenIn, tokenOut [20]byte,
	amountIn *big.Int,
	maxHops int,
) ([]PoolEdge, *big.Int, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check cache first
	cacheKey := routeCacheKey{
		TokenIn:  tokenIn,
		TokenOut: tokenOut,
		AmountIn: quantizeAmount(amountIn),
	}
	if cached, ok := g.routeCache[cacheKey]; ok {
		atomic.AddUint64(&g.cacheHits, 1)
		return cached.Route, cached.AmountOut, nil
	}
	atomic.AddUint64(&g.cacheMiss, 1)

	// Initialize priority queue
	pq := make(routeHeap, 0)
	heap.Init(&pq)

	// Start node
	startNode := &routeNode{
		token:     tokenIn,
		amountOut: new(big.Int).Set(amountIn),
		gasUsed:   0,
		path:      nil,
	}
	heap.Push(&pq, startNode)

	// Track best amount for each (token, hop_count) pair
	best := make(map[[20]byte]*big.Int)

	var bestRoute []PoolEdge
	var bestOutput *big.Int

	for pq.Len() > 0 {
		current := heap.Pop(&pq).(*routeNode)

		// Check if we reached destination
		if current.token == tokenOut {
			if bestOutput == nil || current.amountOut.Cmp(bestOutput) > 0 {
				bestOutput = new(big.Int).Set(current.amountOut)
				bestRoute = make([]PoolEdge, len(current.path))
				copy(bestRoute, current.path)
			}
			continue
		}

		// Skip if we've seen better
		if prevBest, ok := best[current.token]; ok {
			if prevBest.Cmp(current.amountOut) >= 0 {
				continue
			}
		}
		best[current.token] = new(big.Int).Set(current.amountOut)

		// Max hops check
		if len(current.path) >= maxHops {
			continue
		}

		// Explore neighbors
		edges := g.adjacency[current.token]
		for _, edge := range edges {
			// Determine output token
			var nextToken [20]byte
			var zeroForOne bool
			if edge.Token0 == current.token {
				nextToken = edge.Token1
				zeroForOne = true
			} else {
				nextToken = edge.Token0
				zeroForOne = false
			}

			// Skip if we'd revisit a token (no loops)
			visited := false
			for _, p := range current.path {
				if p.Token0 == nextToken || p.Token1 == nextToken {
					visited = true
					break
				}
			}
			if visited && nextToken != tokenOut {
				continue
			}

			// Calculate output amount
			outputAmount := g.simulateSwap(
				current.amountOut,
				edge.Liquidity,
				edge.Fee,
				zeroForOne,
			)

			if outputAmount.Sign() <= 0 {
				continue
			}

			// Create new node
			newPath := make([]PoolEdge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = edge

			newNode := &routeNode{
				token:     nextToken,
				amountOut: outputAmount,
				gasUsed:   current.gasUsed + 30000, // ~30k gas per hop
				path:      newPath,
			}

			heap.Push(&pq, newNode)
		}
	}

	if bestRoute == nil {
		return nil, nil, ErrNoRouteFound
	}

	return bestRoute, bestOutput, nil
}

// simulateSwap simulates a swap and returns output amount.
func (g *PoolGraph) simulateSwap(
	amountIn *big.Int,
	liquidity Liquidity128,
	fee uint32,
	zeroForOne bool,
) *big.Int {
	liq := liquidity.ToBigInt()
	if liq.Sign() == 0 {
		return big.NewInt(0)
	}

	// Apply fee
	feeMultiplier := int64(1_000_000 - fee)
	amountAfterFee := new(big.Int).Mul(amountIn, big.NewInt(feeMultiplier))
	amountAfterFee.Div(amountAfterFee, big.NewInt(1_000_000))

	// Constant product: out = in * L / (L + in)
	numerator := new(big.Int).Mul(amountAfterFee, liq)
	denominator := new(big.Int).Add(liq, amountAfterFee)
	if denominator.Sign() == 0 {
		return big.NewInt(0)
	}

	return numerator.Div(numerator, denominator)
}

// quantizeAmount converts amount to cache key bucket.
func quantizeAmount(amount *big.Int) uint64 {
	if amount == nil {
		return 0
	}
	// Quantize to nearest power of 2 for cache efficiency
	bits := amount.BitLen()
	if bits <= 64 {
		return amount.Uint64()
	}
	// For large amounts, use top 64 bits
	shifted := new(big.Int).Rsh(amount, uint(bits-64))
	return shifted.Uint64()
}

// ErrNoRouteFound indicates no valid route exists.
var ErrNoRouteFound = errors.New("no route found")

// =============================================================================
// Batch Route Optimization (GPU-accelerated)
// =============================================================================

// BatchRouteRequest represents a batch route optimization request.
type BatchRouteRequest struct {
	TokenIn    [20]byte
	TokenOut   [20]byte
	AmountIn   *big.Int
	MaxHops    int
	Deadline   uint64 // Max block for route validity
}

// BatchRouteResult holds the result of batch route optimization.
type BatchRouteResult struct {
	Route       []PoolEdge
	AmountOut   *big.Int
	PriceImpact uint32 // Basis points
	GasEstimate uint64
	Success     bool
	ErrorMsg    string
}

// Router provides GPU-accelerated route optimization.
type Router struct {
	graph *PoolGraph
	acc   *Accelerator

	// Parallel worker pool
	workerCount int
	workChan    chan routeWork
	resultChan  chan routeResult
	done        chan struct{}
}

type routeWork struct {
	idx     int
	request BatchRouteRequest
}

type routeResult struct {
	idx    int
	result BatchRouteResult
}

// NewRouter creates a GPU-accelerated router.
func NewRouter(graph *PoolGraph, acc *Accelerator) *Router {
	r := &Router{
		graph:       graph,
		acc:         acc,
		workerCount: 8, // 8 parallel workers
		workChan:    make(chan routeWork, 1024),
		resultChan:  make(chan routeResult, 1024),
		done:        make(chan struct{}),
	}

	// Start workers
	for i := 0; i < r.workerCount; i++ {
		go r.routeWorker()
	}

	return r
}

// Close shuts down the router.
func (r *Router) Close() {
	close(r.done)
}

// routeWorker processes route requests.
func (r *Router) routeWorker() {
	for {
		select {
		case <-r.done:
			return
		case work := <-r.workChan:
			result := r.findRoute(work.request)
			r.resultChan <- routeResult{idx: work.idx, result: result}
		}
	}
}

// findRoute finds optimal route for a single request.
func (r *Router) findRoute(req BatchRouteRequest) BatchRouteResult {
	result := BatchRouteResult{Success: true}

	route, amountOut, err := r.graph.FindOptimalRoute(
		req.TokenIn,
		req.TokenOut,
		req.AmountIn,
		req.MaxHops,
	)

	if err != nil {
		result.Success = false
		result.ErrorMsg = err.Error()
		return result
	}

	result.Route = route
	result.AmountOut = amountOut
	result.GasEstimate = uint64(len(route)) * 30000

	// Calculate price impact
	if req.AmountIn.Sign() > 0 && amountOut.Sign() > 0 {
		// impact = (amountIn - amountOut) / amountIn * 10000
		diff := new(big.Int).Sub(req.AmountIn, amountOut)
		impact := new(big.Int).Mul(diff, big.NewInt(10000))
		impact.Div(impact, req.AmountIn)
		if impact.Sign() >= 0 && impact.IsUint64() {
			result.PriceImpact = uint32(impact.Uint64())
		}
	}

	return result
}

// BatchOptimize finds optimal routes for multiple requests.
func (r *Router) BatchOptimize(requests []BatchRouteRequest) []BatchRouteResult {
	n := len(requests)
	if n == 0 {
		return nil
	}

	results := make([]BatchRouteResult, n)
	pending := n

	// Submit all work
	go func() {
		for i, req := range requests {
			r.workChan <- routeWork{idx: i, request: req}
		}
	}()

	// Collect results
	for pending > 0 {
		res := <-r.resultChan
		results[res.idx] = res.result
		pending--
	}

	return results
}

// =============================================================================
// A* Pathfinding with Heuristics
// =============================================================================

// AStarRouter uses A* algorithm with liquidity-based heuristics.
type AStarRouter struct {
	graph *PoolGraph

	// Heuristic weights
	liquidityWeight float64
	feeWeight       float64
	hopWeight       float64
}

// NewAStarRouter creates an A* router.
func NewAStarRouter(graph *PoolGraph) *AStarRouter {
	return &AStarRouter{
		graph:           graph,
		liquidityWeight: 0.4,
		feeWeight:       0.3,
		hopWeight:       0.3,
	}
}

// astarNode represents a node in A* search.
type astarNode struct {
	token    [20]byte
	amount   *big.Int
	gScore   float64 // Cost to reach this node
	fScore   float64 // gScore + heuristic
	path     []PoolEdge
	index    int
}

// astarHeap implements heap.Interface for A*.
type astarHeap []*astarNode

func (h astarHeap) Len() int            { return len(h) }
func (h astarHeap) Less(i, j int) bool  { return h[i].fScore < h[j].fScore }
func (h astarHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *astarHeap) Push(x interface{}) { *h = append(*h, x.(*astarNode)) }
func (h *astarHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

// FindRoute finds optimal route using A* algorithm.
func (r *AStarRouter) FindRoute(
	tokenIn, tokenOut [20]byte,
	amountIn *big.Int,
	maxHops int,
) ([]PoolEdge, *big.Int, error) {
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()

	openSet := make(astarHeap, 0)
	heap.Init(&openSet)

	startNode := &astarNode{
		token:  tokenIn,
		amount: new(big.Int).Set(amountIn),
		gScore: 0,
		fScore: r.heuristic(tokenIn, tokenOut, amountIn),
		path:   nil,
	}
	heap.Push(&openSet, startNode)

	visited := make(map[[20]byte]float64)

	for openSet.Len() > 0 {
		current := heap.Pop(&openSet).(*astarNode)

		// Reached destination
		if current.token == tokenOut {
			return current.path, current.amount, nil
		}

		// Skip if we've seen better
		if prevScore, ok := visited[current.token]; ok && prevScore <= current.gScore {
			continue
		}
		visited[current.token] = current.gScore

		// Max hops
		if len(current.path) >= maxHops {
			continue
		}

		// Explore neighbors
		for _, edge := range r.graph.adjacency[current.token] {
			var nextToken [20]byte
			var zeroForOne bool
			if edge.Token0 == current.token {
				nextToken = edge.Token1
				zeroForOne = true
			} else {
				nextToken = edge.Token0
				zeroForOne = false
			}

			// Skip loops
			if _, seen := visited[nextToken]; seen && nextToken != tokenOut {
				continue
			}

			// Calculate output
			outputAmount := r.graph.simulateSwap(
				current.amount,
				edge.Liquidity,
				edge.Fee,
				zeroForOne,
			)

			if outputAmount.Sign() <= 0 {
				continue
			}

			// Calculate costs
			edgeCost := r.edgeCost(edge, current.amount)
			newGScore := current.gScore + edgeCost
			newFScore := newGScore + r.heuristic(nextToken, tokenOut, outputAmount)

			newPath := make([]PoolEdge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = edge

			newNode := &astarNode{
				token:  nextToken,
				amount: outputAmount,
				gScore: newGScore,
				fScore: newFScore,
				path:   newPath,
			}

			heap.Push(&openSet, newNode)
		}
	}

	return nil, nil, ErrNoRouteFound
}

// heuristic estimates cost to reach target.
func (r *AStarRouter) heuristic(from, to [20]byte, amount *big.Int) float64 {
	if from == to {
		return 0
	}

	// Base cost for one hop
	baseCost := r.hopWeight

	// Adjust based on available liquidity paths
	edges := r.graph.adjacency[from]
	if len(edges) == 0 {
		return math.Inf(1)
	}

	// Estimate based on best edge liquidity
	var maxLiq uint64
	for _, e := range edges {
		liq := e.Liquidity.Lo
		if liq > maxLiq {
			maxLiq = liq
		}
	}

	if maxLiq > 0 {
		// Lower cost for higher liquidity
		liqFactor := float64(amount.Uint64()) / float64(maxLiq)
		if liqFactor > 1 {
			liqFactor = 1
		}
		baseCost += r.liquidityWeight * liqFactor
	}

	return baseCost
}

// edgeCost calculates the cost of traversing an edge.
func (r *AStarRouter) edgeCost(edge PoolEdge, amount *big.Int) float64 {
	cost := r.hopWeight

	// Fee cost
	feeCost := float64(edge.Fee) / 1_000_000.0
	cost += r.feeWeight * feeCost

	// Liquidity cost (higher for low liquidity relative to amount)
	liq := edge.Liquidity.ToBigInt()
	if liq.Sign() > 0 {
		ratio := new(big.Int).Div(amount, liq)
		liqCost := float64(ratio.Uint64())
		if liqCost > 1 {
			liqCost = 1
		}
		cost += r.liquidityWeight * liqCost
	}

	return cost
}

// =============================================================================
// GPU-Accelerated Parallel Route Search
// =============================================================================

// ParallelRouter uses GPU to search multiple routes simultaneously.
type ParallelRouter struct {
	graph *PoolGraph
	acc   *Accelerator
}

// NewParallelRouter creates a GPU-accelerated parallel router.
func NewParallelRouter(graph *PoolGraph, acc *Accelerator) *ParallelRouter {
	return &ParallelRouter{
		graph: graph,
		acc:   acc,
	}
}

// FindBestRoutes finds top-k routes for a swap.
func (r *ParallelRouter) FindBestRoutes(
	tokenIn, tokenOut [20]byte,
	amountIn *big.Int,
	k int,
	maxHops int,
) ([][]PoolEdge, []*big.Int, error) {
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()

	// Generate candidate routes using BFS
	candidates := r.generateCandidates(tokenIn, tokenOut, maxHops, k*10)

	if len(candidates) == 0 {
		return nil, nil, ErrNoRouteFound
	}

	// Convert to GPU input format
	inputs := make([]RouteInput, len(candidates))
	for i, candidate := range candidates {
		inputs[i] = r.routeToInput(candidate, amountIn)
	}

	// Batch evaluate on GPU
	outputs, err := r.acc.BatchRoute(inputs)
	if err != nil {
		return nil, nil, err
	}

	// Sort by output amount and take top k
	type routeScore struct {
		route  []PoolEdge
		amount *big.Int
	}
	scores := make([]routeScore, 0, len(outputs))
	for i, out := range outputs {
		if out.Success {
			scores = append(scores, routeScore{
				route:  candidates[i],
				amount: out.AmountOut.ToBigInt(),
			})
		}
	}

	// Sort descending by amount
	for i := 0; i < len(scores); i++ {
		for j := i + 1; j < len(scores); j++ {
			if scores[j].amount.Cmp(scores[i].amount) > 0 {
				scores[i], scores[j] = scores[j], scores[i]
			}
		}
	}

	// Take top k
	if len(scores) > k {
		scores = scores[:k]
	}

	routes := make([][]PoolEdge, len(scores))
	amounts := make([]*big.Int, len(scores))
	for i, s := range scores {
		routes[i] = s.route
		amounts[i] = s.amount
	}

	return routes, amounts, nil
}

// generateCandidates uses BFS to find candidate routes.
func (r *ParallelRouter) generateCandidates(
	tokenIn, tokenOut [20]byte,
	maxHops, maxCandidates int,
) [][]PoolEdge {
	type state struct {
		token [20]byte
		path  []PoolEdge
	}

	candidates := make([][]PoolEdge, 0)
	queue := []state{{token: tokenIn, path: nil}}
	visited := make(map[[20]byte]bool)

	for len(queue) > 0 && len(candidates) < maxCandidates {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > maxHops {
			continue
		}

		edges := r.graph.adjacency[current.token]
		for _, edge := range edges {
			var nextToken [20]byte
			if edge.Token0 == current.token {
				nextToken = edge.Token1
			} else {
				nextToken = edge.Token0
			}

			// Skip visited (except destination)
			if visited[nextToken] && nextToken != tokenOut {
				continue
			}

			newPath := make([]PoolEdge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = edge

			if nextToken == tokenOut {
				candidates = append(candidates, newPath)
			} else if len(newPath) < maxHops {
				queue = append(queue, state{token: nextToken, path: newPath})
			}
		}

		visited[current.token] = true
	}

	return candidates
}

// routeToInput converts a route to GPU input format.
func (r *ParallelRouter) routeToInput(route []PoolEdge, amountIn *big.Int) RouteInput {
	input := RouteInput{
		NumHops:     uint8(len(route)),
		PoolIDs:     make([][32]byte, len(route)),
		SqrtPrices:  make([]SqrtPriceX96, len(route)),
		Liquidities: make([]Liquidity128, len(route)),
		Fees:        make([]uint32, len(route)),
	}
	input.AmountIn.FromBigInt(amountIn)

	for i, edge := range route {
		input.PoolIDs[i] = edge.PoolID
		input.SqrtPrices[i] = edge.SqrtPriceX96
		input.Liquidities[i] = edge.Liquidity
		input.Fees[i] = edge.Fee
	}

	return input
}

// =============================================================================
// Price Impact Calculator
// =============================================================================

// PriceImpactCalc calculates price impact for routes.
type PriceImpactCalc struct {
	acc *Accelerator
}

// NewPriceImpactCalc creates a price impact calculator.
func NewPriceImpactCalc(acc *Accelerator) *PriceImpactCalc {
	return &PriceImpactCalc{acc: acc}
}

// CalculateImpact calculates price impact for a route.
func (c *PriceImpactCalc) CalculateImpact(
	route []PoolEdge,
	amountIn *big.Int,
) (uint32, error) {
	if len(route) == 0 {
		return 0, nil
	}

	// Create route input
	input := RouteInput{
		NumHops:     uint8(len(route)),
		PoolIDs:     make([][32]byte, len(route)),
		SqrtPrices:  make([]SqrtPriceX96, len(route)),
		Liquidities: make([]Liquidity128, len(route)),
		Fees:        make([]uint32, len(route)),
	}
	input.AmountIn.FromBigInt(amountIn)

	for i, edge := range route {
		input.PoolIDs[i] = edge.PoolID
		input.SqrtPrices[i] = edge.SqrtPriceX96
		input.Liquidities[i] = edge.Liquidity
		input.Fees[i] = edge.Fee
	}

	// Batch with single input
	outputs, err := c.acc.BatchRoute([]RouteInput{input})
	if err != nil {
		return 0, err
	}

	if len(outputs) == 0 || !outputs[0].Success {
		return 0, ErrNoRouteFound
	}

	return outputs[0].PriceImpact, nil
}

// BatchCalculateImpact calculates price impact for multiple routes.
func (c *PriceImpactCalc) BatchCalculateImpact(
	routes [][]PoolEdge,
	amountsIn []*big.Int,
) ([]uint32, error) {
	if len(routes) != len(amountsIn) {
		return nil, ErrInvalidInput
	}

	inputs := make([]RouteInput, len(routes))
	for i, route := range routes {
		inputs[i] = RouteInput{
			NumHops:     uint8(len(route)),
			PoolIDs:     make([][32]byte, len(route)),
			SqrtPrices:  make([]SqrtPriceX96, len(route)),
			Liquidities: make([]Liquidity128, len(route)),
			Fees:        make([]uint32, len(route)),
		}
		inputs[i].AmountIn.FromBigInt(amountsIn[i])

		for j, edge := range route {
			inputs[i].PoolIDs[j] = edge.PoolID
			inputs[i].SqrtPrices[j] = edge.SqrtPriceX96
			inputs[i].Liquidities[j] = edge.Liquidity
			inputs[i].Fees[j] = edge.Fee
		}
	}

	outputs, err := c.acc.BatchRoute(inputs)
	if err != nil {
		return nil, err
	}

	impacts := make([]uint32, len(outputs))
	for i, out := range outputs {
		if out.Success {
			impacts[i] = out.PriceImpact
		}
	}

	return impacts, nil
}
