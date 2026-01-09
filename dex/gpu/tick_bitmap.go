// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"math/bits"
	"sync"
	"sync/atomic"
)

// =============================================================================
// Tick Bitmap for Concentrated Liquidity
// =============================================================================

// TickBitmap manages tick initialization state using a compressed bitmap.
// Each word stores 256 ticks (one bit per tick).
// Optimized for parallel GPU operations.
type TickBitmap struct {
	mu sync.RWMutex

	// bitmap stores tick initialization state
	// Key: word position (tick / 256)
	// Value: 256-bit word as [4]uint64
	bitmap map[int16][4]uint64

	// Cache of recently accessed words
	cache     map[int16][4]uint64
	cacheSize int
	cacheHits uint64
	cacheMiss uint64
}

// NewTickBitmap creates a new tick bitmap.
func NewTickBitmap() *TickBitmap {
	return &TickBitmap{
		bitmap:    make(map[int16][4]uint64),
		cache:     make(map[int16][4]uint64),
		cacheSize: 1024,
	}
}

// wordPos returns the word position for a tick.
func wordPos(tick int32) int16 {
	// tick / 256, rounding toward negative infinity
	if tick >= 0 {
		return int16(tick >> 8)
	}
	return int16((tick - 255) >> 8)
}

// bitPos returns the bit position within a word (0-255).
func bitPos(tick int32) uint8 {
	// tick % 256, always positive
	pos := tick & 0xFF
	if pos < 0 {
		pos += 256
	}
	return uint8(pos)
}

// FlipTick toggles the tick's initialized state.
func (tb *TickBitmap) FlipTick(tick int32, tickSpacing int32) {
	// Ensure tick is on spacing boundary
	if tick%tickSpacing != 0 {
		return
	}
	compressed := tick / tickSpacing

	tb.mu.Lock()
	defer tb.mu.Unlock()

	wp := wordPos(compressed)
	bp := bitPos(compressed)

	word := tb.bitmap[wp]
	wordIdx := bp / 64
	bitIdx := bp % 64

	word[wordIdx] ^= 1 << bitIdx
	tb.bitmap[wp] = word

	// Invalidate cache
	delete(tb.cache, wp)
}

// IsInitialized returns whether a tick is initialized.
func (tb *TickBitmap) IsInitialized(tick int32, tickSpacing int32) bool {
	if tick%tickSpacing != 0 {
		return false
	}
	compressed := tick / tickSpacing

	tb.mu.RLock()
	defer tb.mu.RUnlock()

	wp := wordPos(compressed)
	bp := bitPos(compressed)

	word := tb.bitmap[wp]
	wordIdx := bp / 64
	bitIdx := bp % 64

	return (word[wordIdx] & (1 << bitIdx)) != 0
}

// =============================================================================
// Next Initialized Tick Search (Parallel)
// =============================================================================

// NextInitializedTick finds the next initialized tick.
// If lte is true, searches left (lower ticks), otherwise right (higher).
// Returns (nextTick, isInitialized).
func (tb *TickBitmap) NextInitializedTick(
	tick int32,
	tickSpacing int32,
	lte bool,
) (int32, bool) {
	compressed := tick / tickSpacing

	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if lte {
		return tb.nextInitializedTickLeft(compressed, tickSpacing)
	}
	return tb.nextInitializedTickRight(compressed, tickSpacing)
}

// nextInitializedTickLeft searches left (toward lower ticks).
func (tb *TickBitmap) nextInitializedTickLeft(
	compressed int32,
	tickSpacing int32,
) (int32, bool) {
	wp := wordPos(compressed)
	bp := bitPos(compressed)

	// Create mask for bits at or below bp
	word := tb.bitmap[wp]

	// Search within current word
	for i := int(bp/64) + 1; i > 0; i-- {
		wordIdx := i - 1
		w := word[wordIdx]

		// Mask off bits above bp if in same sub-word
		if wordIdx == int(bp/64) {
			bitMask := uint64(1)<<(bp%64+1) - 1
			w &= bitMask
		}

		if w != 0 {
			// Find highest set bit
			highBit := 63 - bits.LeadingZeros64(w)
			foundTick := (int32(wp)*256 + int32(wordIdx)*64 + int32(highBit)) * tickSpacing
			return foundTick, true
		}
	}

	// Search previous words
	for searchWp := wp - 1; searchWp >= -3447; searchWp-- {
		word := tb.bitmap[searchWp]

		// Search from highest sub-word
		for wordIdx := 3; wordIdx >= 0; wordIdx-- {
			w := word[wordIdx]
			if w != 0 {
				highBit := 63 - bits.LeadingZeros64(w)
				foundTick := (int32(searchWp)*256 + int32(wordIdx)*64 + int32(highBit)) * tickSpacing
				return foundTick, true
			}
		}
	}

	// No initialized tick found
	return MinTickValue * tickSpacing, false
}

// nextInitializedTickRight searches right (toward higher ticks).
func (tb *TickBitmap) nextInitializedTickRight(
	compressed int32,
	tickSpacing int32,
) (int32, bool) {
	wp := wordPos(compressed)
	bp := bitPos(compressed)

	word := tb.bitmap[wp]

	// Search within current word, starting from bp+1
	startBit := bp + 1
	for wordIdx := int(startBit / 64); wordIdx < 4; wordIdx++ {
		w := word[wordIdx]

		// Mask off bits below startBit if in same sub-word
		if wordIdx == int(startBit/64) {
			bitMask := ^(uint64(1)<<(startBit%64) - 1)
			w &= bitMask
		}

		if w != 0 {
			lowBit := bits.TrailingZeros64(w)
			foundTick := (int32(wp)*256 + int32(wordIdx)*64 + int32(lowBit)) * tickSpacing
			return foundTick, true
		}
	}

	// Search subsequent words
	for searchWp := wp + 1; searchWp <= 3466; searchWp++ {
		word := tb.bitmap[searchWp]

		for wordIdx := 0; wordIdx < 4; wordIdx++ {
			w := word[wordIdx]
			if w != 0 {
				lowBit := bits.TrailingZeros64(w)
				foundTick := (int32(searchWp)*256 + int32(wordIdx)*64 + int32(lowBit)) * tickSpacing
				return foundTick, true
			}
		}
	}

	return MaxTickValue * tickSpacing, false
}

// Min/max tick values
const (
	MinTickValue int32 = -887272
	MaxTickValue int32 = 887272
)

// =============================================================================
// Batch Tick Operations (GPU-accelerated)
// =============================================================================

// TickSearchInput represents a batch tick search request.
type TickSearchInput struct {
	PoolID      [32]byte
	CurrentTick int32
	TickSpacing int32
	SearchLeft  bool
}

// TickSearchOutput represents a batch tick search result.
type TickSearchOutput struct {
	NextTick      int32
	IsInitialized bool
}

// BatchNextInitializedTick finds next initialized ticks for multiple queries.
func (tb *TickBitmap) BatchNextInitializedTick(
	inputs []TickSearchInput,
) []TickSearchOutput {
	n := len(inputs)
	outputs := make([]TickSearchOutput, n)

	// Use parallel processing for large batches
	if n >= 64 {
		var wg sync.WaitGroup
		chunkSize := 64

		for i := 0; i < n; i += chunkSize {
			end := i + chunkSize
			if end > n {
				end = n
			}
			wg.Add(1)
			go func(start, stop int) {
				defer wg.Done()
				for j := start; j < stop; j++ {
					in := &inputs[j]
					nextTick, initialized := tb.NextInitializedTick(
						in.CurrentTick,
						in.TickSpacing,
						in.SearchLeft,
					)
					outputs[j] = TickSearchOutput{
						NextTick:      nextTick,
						IsInitialized: initialized,
					}
				}
			}(i, end)
		}

		wg.Wait()
	} else {
		for i := 0; i < n; i++ {
			in := &inputs[i]
			nextTick, initialized := tb.NextInitializedTick(
				in.CurrentTick,
				in.TickSpacing,
				in.SearchLeft,
			)
			outputs[i] = TickSearchOutput{
				NextTick:      nextTick,
				IsInitialized: initialized,
			}
		}
	}

	return outputs
}

// =============================================================================
// Tick State Management
// =============================================================================

// TickState holds state for an initialized tick.
type TickState struct {
	LiquidityGross        *Liquidity128 // Total liquidity referencing this tick
	LiquidityNet          *Liquidity128 // Net liquidity delta when crossing (signed)
	FeeGrowthOutside0X128 *Liquidity128
	FeeGrowthOutside1X128 *Liquidity128
	Initialized           bool
}

// TickStateMap manages tick states.
type TickStateMap struct {
	mu     sync.RWMutex
	states map[int32]*TickState
}

// NewTickStateMap creates a new tick state map.
func NewTickStateMap() *TickStateMap {
	return &TickStateMap{
		states: make(map[int32]*TickState),
	}
}

// Get returns the state for a tick.
func (m *TickStateMap) Get(tick int32) *TickState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.states[tick]
}

// Update updates a tick's state.
func (m *TickStateMap) Update(tick int32, state *TickState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[tick] = state
}

// BatchUpdate updates multiple tick states.
func (m *TickStateMap) BatchUpdate(updates map[int32]*TickState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tick, state := range updates {
		m.states[tick] = state
	}
}

// =============================================================================
// Position Bitmap (for tracking active positions)
// =============================================================================

// PositionBitmap tracks which positions exist for quick lookup.
type PositionBitmap struct {
	mu     sync.RWMutex
	bitmap map[[32]byte]struct{}
	count  uint64
}

// NewPositionBitmap creates a new position bitmap.
func NewPositionBitmap() *PositionBitmap {
	return &PositionBitmap{
		bitmap: make(map[[32]byte]struct{}),
	}
}

// Add adds a position to the bitmap.
func (pb *PositionBitmap) Add(positionKey [32]byte) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if _, exists := pb.bitmap[positionKey]; !exists {
		pb.bitmap[positionKey] = struct{}{}
		atomic.AddUint64(&pb.count, 1)
	}
}

// Remove removes a position from the bitmap.
func (pb *PositionBitmap) Remove(positionKey [32]byte) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if _, exists := pb.bitmap[positionKey]; exists {
		delete(pb.bitmap, positionKey)
		atomic.AddUint64(&pb.count, ^uint64(0)) // Decrement
	}
}

// Exists checks if a position exists.
func (pb *PositionBitmap) Exists(positionKey [32]byte) bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	_, exists := pb.bitmap[positionKey]
	return exists
}

// Count returns the number of positions.
func (pb *PositionBitmap) Count() uint64 {
	return atomic.LoadUint64(&pb.count)
}

// =============================================================================
// Batch Position Updates
// =============================================================================

// PositionUpdate represents a position modification.
type PositionUpdate struct {
	PositionKey [32]byte
	TickLower   int32
	TickUpper   int32
	LiqDelta    Liquidity128
	IsAdd       bool
}

// PositionUpdateResult holds the result of a position update.
type PositionUpdateResult struct {
	Amount0       Liquidity128
	Amount1       Liquidity128
	FeesCollected Liquidity128
	Success       bool
}

// BatchPositionUpdater processes position updates in parallel.
type BatchPositionUpdater struct {
	tickBitmap *TickBitmap
	tickStates *TickStateMap
	positions  *PositionBitmap
	acc        *Accelerator
}

// NewBatchPositionUpdater creates a new batch position updater.
func NewBatchPositionUpdater(
	tickBitmap *TickBitmap,
	tickStates *TickStateMap,
	positions *PositionBitmap,
	acc *Accelerator,
) *BatchPositionUpdater {
	return &BatchPositionUpdater{
		tickBitmap: tickBitmap,
		tickStates: tickStates,
		positions:  positions,
		acc:        acc,
	}
}

// ProcessUpdates processes multiple position updates.
func (u *BatchPositionUpdater) ProcessUpdates(
	updates []PositionUpdate,
	poolSqrtPrice SqrtPriceX96,
	poolLiquidity Liquidity128,
	currentTick int32,
	tickSpacing int32,
) []PositionUpdateResult {
	n := len(updates)
	results := make([]PositionUpdateResult, n)

	// Convert to GPU liquidity inputs
	inputs := make([]LiquidityInput, n)
	for i, upd := range updates {
		inputs[i] = LiquidityInput{
			PoolID:       upd.PositionKey, // Reuse as pool ID
			SqrtPriceX96: poolSqrtPrice,
			Liquidity:    poolLiquidity,
			CurrentTick:  currentTick,
			TickLower:    upd.TickLower,
			TickUpper:    upd.TickUpper,
			LiqDelta:     upd.LiqDelta,
			IsAdd:        upd.IsAdd,
		}
	}

	// Process on GPU
	outputs, err := u.acc.BatchLiquidity(inputs)
	if err != nil {
		// Mark all as failed
		for i := range results {
			results[i].Success = false
		}
		return results
	}

	// Update tick bitmaps and states
	tickUpdates := make(map[int32]*TickState)

	for i, upd := range updates {
		out := outputs[i]
		results[i] = PositionUpdateResult{
			Amount0:       out.Amount0,
			Amount1:       out.Amount1,
			FeesCollected: out.FeeGrowth0, // Simplified
			Success:       out.Success,
		}

		if out.Success {
			// Update position bitmap
			if upd.IsAdd {
				u.positions.Add(upd.PositionKey)
			}

			// Update tick states
			liqDelta := upd.LiqDelta.ToBigInt()
			for _, tick := range []int32{upd.TickLower, upd.TickUpper} {
				state := u.tickStates.Get(tick)
				if state == nil {
					state = &TickState{
						LiquidityGross: &Liquidity128{},
						LiquidityNet:   &Liquidity128{},
					}
				}

				// Update gross liquidity
				gross := state.LiquidityGross.ToBigInt()
				gross.Add(gross, liqDelta)
				state.LiquidityGross.FromBigInt(gross)

				// Update net liquidity (add at lower, subtract at upper)
				net := state.LiquidityNet.ToBigInt()
				if tick == upd.TickLower {
					net.Add(net, liqDelta)
				} else {
					net.Sub(net, liqDelta)
				}
				state.LiquidityNet.FromBigInt(net)

				// Update initialized state
				state.Initialized = gross.Sign() > 0
				tickUpdates[tick] = state

				// Update bitmap
				if state.Initialized {
					u.tickBitmap.FlipTick(tick, tickSpacing)
				}
			}
		}
	}

	// Batch update tick states
	u.tickStates.BatchUpdate(tickUpdates)

	return results
}

// =============================================================================
// Cross-Tick Calculations
// =============================================================================

// CrossTickInput represents a tick crossing calculation.
type CrossTickInput struct {
	PoolID         [32]byte
	TickToCross    int32
	FeeGrowth0X128 Liquidity128
	FeeGrowth1X128 Liquidity128
	CurrentLiq     Liquidity128
	ZeroForOne     bool
}

// CrossTickOutput holds the result of crossing a tick.
type CrossTickOutput struct {
	NewLiquidity    Liquidity128
	FeeGrowthDelta0 Liquidity128
	FeeGrowthDelta1 Liquidity128
}

// BatchCrossTick calculates tick crossing effects in parallel.
func BatchCrossTick(
	inputs []CrossTickInput,
	tickStates *TickStateMap,
) []CrossTickOutput {
	n := len(inputs)
	outputs := make([]CrossTickOutput, n)

	var wg sync.WaitGroup
	chunkSize := 64

	for i := 0; i < n; i += chunkSize {
		end := i + chunkSize
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(start, stop int) {
			defer wg.Done()
			for j := start; j < stop; j++ {
				in := &inputs[j]
				state := tickStates.Get(in.TickToCross)

				if state == nil {
					outputs[j] = CrossTickOutput{
						NewLiquidity: in.CurrentLiq,
					}
					continue
				}

				// Calculate new liquidity
				currentLiq := in.CurrentLiq.ToBigInt()
				netLiq := state.LiquidityNet.ToBigInt()

				if in.ZeroForOne {
					// Crossing down: subtract net liquidity
					currentLiq.Sub(currentLiq, netLiq)
				} else {
					// Crossing up: add net liquidity
					currentLiq.Add(currentLiq, netLiq)
				}

				outputs[j].NewLiquidity.FromBigInt(currentLiq)

				// Calculate fee growth deltas
				if state.FeeGrowthOutside0X128 != nil {
					outputs[j].FeeGrowthDelta0 = *state.FeeGrowthOutside0X128
				}
				if state.FeeGrowthOutside1X128 != nil {
					outputs[j].FeeGrowthDelta1 = *state.FeeGrowthOutside1X128
				}
			}
		}(i, end)
	}

	wg.Wait()
	return outputs
}

// =============================================================================
// Liquidity at Price Calculator
// =============================================================================

// LiquidityAtPrice calculates available liquidity at a target price.
type LiquidityAtPrice struct {
	tickBitmap *TickBitmap
	tickStates *TickStateMap
}

// NewLiquidityAtPrice creates a liquidity calculator.
func NewLiquidityAtPrice(
	tickBitmap *TickBitmap,
	tickStates *TickStateMap,
) *LiquidityAtPrice {
	return &LiquidityAtPrice{
		tickBitmap: tickBitmap,
		tickStates: tickStates,
	}
}

// Calculate computes liquidity between two prices.
func (l *LiquidityAtPrice) Calculate(
	startTick, endTick int32,
	startLiquidity Liquidity128,
	tickSpacing int32,
) Liquidity128 {
	if startTick == endTick {
		return startLiquidity
	}

	liq := startLiquidity.ToBigInt()
	zeroForOne := startTick > endTick

	currentTick := startTick
	for {
		// Find next initialized tick
		var nextTick int32
		var initialized bool

		if zeroForOne {
			nextTick, initialized = l.tickBitmap.NextInitializedTick(
				currentTick-1, tickSpacing, true,
			)
			if nextTick < endTick {
				nextTick = endTick
			}
		} else {
			nextTick, initialized = l.tickBitmap.NextInitializedTick(
				currentTick, tickSpacing, false,
			)
			if nextTick > endTick {
				nextTick = endTick
			}
		}

		// Cross tick if initialized
		if initialized && nextTick != endTick {
			state := l.tickStates.Get(nextTick)
			if state != nil {
				netLiq := state.LiquidityNet.ToBigInt()
				if zeroForOne {
					liq.Sub(liq, netLiq)
				} else {
					liq.Add(liq, netLiq)
				}
			}
		}

		currentTick = nextTick
		if (zeroForOne && currentTick <= endTick) ||
			(!zeroForOne && currentTick >= endTick) {
			break
		}
	}

	result := Liquidity128{}
	result.FromBigInt(liq)
	return result
}

// BatchCalculate computes liquidity for multiple price ranges.
func (l *LiquidityAtPrice) BatchCalculate(
	requests []struct {
		StartTick      int32
		EndTick        int32
		StartLiquidity Liquidity128
		TickSpacing    int32
	},
) []Liquidity128 {
	n := len(requests)
	results := make([]Liquidity128, n)

	var wg sync.WaitGroup
	chunkSize := 32

	for i := 0; i < n; i += chunkSize {
		end := i + chunkSize
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(start, stop int) {
			defer wg.Done()
			for j := start; j < stop; j++ {
				req := &requests[j]
				results[j] = l.Calculate(
					req.StartTick,
					req.EndTick,
					req.StartLiquidity,
					req.TickSpacing,
				)
			}
		}(i, end)
	}

	wg.Wait()
	return results
}
