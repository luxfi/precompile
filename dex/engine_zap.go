// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
)

// ZAP AMM message methods (registered on DEX engine's ZAP server)
const (
	ZAPMethodInitialize      = "amm.initialize"
	ZAPMethodSwap            = "amm.swap"
	ZAPMethodModifyLiquidity = "amm.modify_liquidity"
	ZAPMethodDonate          = "amm.donate"
	ZAPMethodQuote           = "amm.quote"
)

// zapClient is the interface for a ZAP binary protocol connection.
type zapClient interface {
	CallRaw(ctx context.Context, method string, payload []byte) ([]byte, error)
	Close() error
}

// ZAPEngine implements Engine via ZAP binary protocol to the DEX engine.
// Zero-copy binary wire format for HFT-grade latency.
type ZAPEngine struct {
	addr    string
	timeout time.Duration

	mu     sync.Mutex
	client zapClient
}

// NewZAPEngine creates a ZAP engine client.
// addr is the DEX engine's ZAP endpoint (e.g., "localhost:9100").
func NewZAPEngine(addr string, timeout time.Duration) *ZAPEngine {
	return &ZAPEngine{
		addr:    addr,
		timeout: timeout,
	}
}

func (z *ZAPEngine) dial(ctx context.Context) (zapClient, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.client != nil {
		return z.client, nil
	}
	c, err := dialZAP(ctx, z.addr)
	if err != nil {
		return nil, fmt.Errorf("ZAP dial %s: %w", z.addr, err)
	}
	z.client = c
	return c, nil
}

// dialZAP establishes a raw TCP connection for ZAP binary protocol.
func dialZAP(ctx context.Context, addr string) (zapClient, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &zapConn{conn: conn}, nil
}

// zapConn wraps a net.Conn to implement zapClient.
type zapConn struct {
	conn net.Conn
}

func (c *zapConn) CallRaw(ctx context.Context, method string, payload []byte) ([]byte, error) {
	// ZAP wire: method_len(2) + method + payload_len(4) + payload
	methodBytes := []byte(method)
	header := make([]byte, 2+len(methodBytes)+4+len(payload))
	binary.BigEndian.PutUint16(header[0:2], uint16(len(methodBytes)))
	copy(header[2:2+len(methodBytes)], methodBytes)
	binary.BigEndian.PutUint32(header[2+len(methodBytes):6+len(methodBytes)], uint32(len(payload)))
	copy(header[6+len(methodBytes):], payload)

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
	}
	if _, err := c.conn.Write(header); err != nil {
		return nil, fmt.Errorf("ZAP write: %w", err)
	}

	// Read response: status(1) + len(4) + data
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
	}
	respHeader := make([]byte, 5)
	if _, err := c.conn.Read(respHeader); err != nil {
		return nil, fmt.Errorf("ZAP read header: %w", err)
	}
	if respHeader[0] != 0 {
		return nil, fmt.Errorf("ZAP error status: %d", respHeader[0])
	}
	respLen := binary.BigEndian.Uint32(respHeader[1:5])
	if respLen == 0 {
		return nil, nil
	}
	resp := make([]byte, respLen)
	if _, err := c.conn.Read(resp); err != nil {
		return nil, fmt.Errorf("ZAP read body: %w", err)
	}
	return resp, nil
}

func (c *zapConn) Close() error {
	return c.conn.Close()
}

func (z *ZAPEngine) call(ctx context.Context, method string, payload []byte) ([]byte, error) {
	c, err := z.dial(ctx)
	if err != nil {
		return nil, err
	}
	return c.CallRaw(ctx, method, payload)
}

// Initialize sends sqrtPriceX96 to DEX engine, gets back the tick.
func (z *ZAPEngine) Initialize(sqrtPriceX96 *big.Int) (int24, error) {
	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	// Wire: sqrtPriceX96 as 32-byte big-endian
	var buf [32]byte
	sqrtPriceX96.FillBytes(buf[:])

	resp, err := z.call(ctx, ZAPMethodInitialize, buf[:])
	if err != nil {
		return 0, fmt.Errorf("ZAP Initialize: %w", err)
	}
	if len(resp) < 4 {
		return 0, fmt.Errorf("ZAP Initialize: response too short (%d bytes)", len(resp))
	}
	tick := int24(int32(binary.BigEndian.Uint32(resp[:4])))
	return tick, nil
}

// Swap sends pool state + swap params to DEX engine.
func (z *ZAPEngine) Swap(pool *PoolState, params SwapParams) (BalanceDelta, error) {
	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	payload := encodeSwapRequest(pool, params)
	resp, err := z.call(ctx, ZAPMethodSwap, payload)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap: %w", err)
	}
	delta, updatedPool, err := decodeSwapResponse(resp)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Swap decode: %w", err)
	}
	// Apply engine's state mutations back to pool
	pool.SqrtPriceX96 = updatedPool.sqrtPriceX96
	pool.Tick = updatedPool.tick
	pool.Liquidity = updatedPool.liquidity
	pool.FeeGrowth0X128 = updatedPool.feeGrowth0X128
	pool.FeeGrowth1X128 = updatedPool.feeGrowth1X128
	return delta, nil
}

// ModifyLiquidity sends pool state + params to DEX engine.
func (z *ZAPEngine) ModifyLiquidity(pool *PoolState, owner common.Address, params ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	payload := encodeModifyLiquidityRequest(pool, owner, params)
	resp, err := z.call(ctx, ZAPMethodModifyLiquidity, payload)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP ModifyLiquidity: %w", err)
	}
	callerDelta, feesAccrued, state, err := decodeModifyLiquidityResponse(resp)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("ZAP ModifyLiquidity decode: %w", err)
	}
	pool.Liquidity = state.liquidity
	pool.FeeGrowth0X128 = state.feeGrowth0X128
	pool.FeeGrowth1X128 = state.feeGrowth1X128
	return callerDelta, feesAccrued, nil
}

// Donate sends amounts to DEX engine for fee distribution.
func (z *ZAPEngine) Donate(pool *PoolState, amount0, amount1 *big.Int) (BalanceDelta, error) {
	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	payload := encodeDonateRequest(pool, amount0, amount1)
	resp, err := z.call(ctx, ZAPMethodDonate, payload)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Donate: %w", err)
	}
	delta, fg0, fg1, err := decodeDonateResponse(resp)
	if err != nil {
		return ZeroBalanceDelta(), fmt.Errorf("ZAP Donate decode: %w", err)
	}
	pool.FeeGrowth0X128 = fg0
	pool.FeeGrowth1X128 = fg1
	return delta, nil
}

// Quote estimates swap output without state mutation.
func (z *ZAPEngine) Quote(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int {
	ctx, cancel := context.WithTimeout(context.Background(), z.timeout)
	defer cancel()

	payload := encodeQuoteRequest(pool, amountIn, zeroForOne)
	resp, err := z.call(ctx, ZAPMethodQuote, payload)
	if err != nil {
		return big.NewInt(0) // quote failure = 0 output
	}
	if len(resp) < 32 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(resp[:32])
}

// Close closes the ZAP connection.
func (z *ZAPEngine) Close() error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.client != nil {
		err := z.client.Close()
		z.client = nil
		return err
	}
	return nil
}

// =========================================================================
// Wire format encode/decode helpers
// =========================================================================

// poolStateWire is the minimal pool state for wire transfer
type poolStateWire struct {
	sqrtPriceX96   *big.Int
	tick           int24
	liquidity      *big.Int
	feeGrowth0X128 *big.Int
	feeGrowth1X128 *big.Int
}

// encodePoolState writes pool state as fixed-size binary:
// sqrtPriceX96[32] + tick[4] + liquidity[32] + feeGrowth0[32] + feeGrowth1[32] = 132 bytes
func encodePoolState(pool *PoolState) []byte {
	buf := make([]byte, 132)
	if pool.SqrtPriceX96 != nil {
		pool.SqrtPriceX96.FillBytes(buf[0:32])
	}
	binary.BigEndian.PutUint32(buf[32:36], uint32(pool.Tick))
	if pool.Liquidity != nil {
		pool.Liquidity.FillBytes(buf[36:68])
	}
	if pool.FeeGrowth0X128 != nil {
		pool.FeeGrowth0X128.FillBytes(buf[68:100])
	}
	if pool.FeeGrowth1X128 != nil {
		pool.FeeGrowth1X128.FillBytes(buf[100:132])
	}
	return buf
}

func decodePoolStateWire(data []byte) poolStateWire {
	return poolStateWire{
		sqrtPriceX96:   new(big.Int).SetBytes(data[0:32]),
		tick:           int24(int32(binary.BigEndian.Uint32(data[32:36]))),
		liquidity:      new(big.Int).SetBytes(data[36:68]),
		feeGrowth0X128: new(big.Int).SetBytes(data[68:100]),
		feeGrowth1X128: new(big.Int).SetBytes(data[100:132]),
	}
}

// encodeSwapRequest: poolState[132] + zeroForOne[1] + amountSpecified[32] + sqrtPriceLimitX96[32] = 197 bytes
func encodeSwapRequest(pool *PoolState, params SwapParams) []byte {
	buf := make([]byte, 197)
	copy(buf[0:132], encodePoolState(pool))
	if params.ZeroForOne {
		buf[132] = 1
	}
	// amountSpecified is signed int256 -- encode as two's complement
	encodeSigned256(buf[133:165], params.AmountSpecified)
	if params.SqrtPriceLimitX96 != nil {
		params.SqrtPriceLimitX96.FillBytes(buf[165:197])
	}
	return buf
}

// decodeSwapResponse: amount0[32] + amount1[32] + poolState[132] = 196 bytes
func decodeSwapResponse(data []byte) (BalanceDelta, poolStateWire, error) {
	if len(data) < 196 {
		return ZeroBalanceDelta(), poolStateWire{}, fmt.Errorf("swap response too short: %d", len(data))
	}
	amount0 := decodeSigned256(data[0:32])
	amount1 := decodeSigned256(data[32:64])
	state := decodePoolStateWire(data[64:196])
	return NewBalanceDelta(amount0, amount1), state, nil
}

// encodeModifyLiquidityRequest: poolState[132] + owner[20] + tickLower[4] + tickUpper[4] + liquidityDelta[32] + salt[32] = 224 bytes
func encodeModifyLiquidityRequest(pool *PoolState, owner common.Address, params ModifyLiquidityParams) []byte {
	buf := make([]byte, 224)
	copy(buf[0:132], encodePoolState(pool))
	copy(buf[132:152], owner.Bytes())
	binary.BigEndian.PutUint32(buf[152:156], uint32(params.TickLower))
	binary.BigEndian.PutUint32(buf[156:160], uint32(params.TickUpper))
	encodeSigned256(buf[160:192], params.LiquidityDelta)
	copy(buf[192:224], params.Salt[:])
	return buf
}

// decodeModifyLiquidityResponse: callerAmount0[32] + callerAmount1[32] + feesAmount0[32] + feesAmount1[32] + liquidity[32] + feeGrowth0[32] + feeGrowth1[32] = 224 bytes
func decodeModifyLiquidityResponse(data []byte) (BalanceDelta, BalanceDelta, poolStateWire, error) {
	if len(data) < 224 {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), poolStateWire{}, fmt.Errorf("modifyLiquidity response too short: %d", len(data))
	}
	callerDelta := NewBalanceDelta(decodeSigned256(data[0:32]), decodeSigned256(data[32:64]))
	feesAccrued := NewBalanceDelta(decodeSigned256(data[64:96]), decodeSigned256(data[96:128]))
	state := poolStateWire{
		liquidity:      new(big.Int).SetBytes(data[128:160]),
		feeGrowth0X128: new(big.Int).SetBytes(data[160:192]),
		feeGrowth1X128: new(big.Int).SetBytes(data[192:224]),
	}
	return callerDelta, feesAccrued, state, nil
}

// encodeDonateRequest: liquidity[32] + feeGrowth0[32] + feeGrowth1[32] + amount0[32] + amount1[32] = 160 bytes
func encodeDonateRequest(pool *PoolState, amount0, amount1 *big.Int) []byte {
	buf := make([]byte, 160)
	if pool.Liquidity != nil {
		pool.Liquidity.FillBytes(buf[0:32])
	}
	if pool.FeeGrowth0X128 != nil {
		pool.FeeGrowth0X128.FillBytes(buf[32:64])
	}
	if pool.FeeGrowth1X128 != nil {
		pool.FeeGrowth1X128.FillBytes(buf[64:96])
	}
	if amount0 != nil {
		amount0.FillBytes(buf[96:128])
	}
	if amount1 != nil {
		amount1.FillBytes(buf[128:160])
	}
	return buf
}

func decodeDonateResponse(data []byte) (BalanceDelta, *big.Int, *big.Int, error) {
	if len(data) < 128 {
		return ZeroBalanceDelta(), nil, nil, fmt.Errorf("donate response too short: %d", len(data))
	}
	delta := NewBalanceDelta(
		new(big.Int).SetBytes(data[0:32]),
		new(big.Int).SetBytes(data[32:64]),
	)
	fg0 := new(big.Int).SetBytes(data[64:96])
	fg1 := new(big.Int).SetBytes(data[96:128])
	return delta, fg0, fg1, nil
}

// encodeQuoteRequest: sqrtPriceX96[32] + tick[4] + liquidity[32] + amountIn[32] + zeroForOne[1] = 101 bytes
func encodeQuoteRequest(pool *Pool, amountIn *big.Int, zeroForOne bool) []byte {
	buf := make([]byte, 101)
	if pool.SqrtPriceX96 != nil {
		pool.SqrtPriceX96.FillBytes(buf[0:32])
	}
	binary.BigEndian.PutUint32(buf[32:36], uint32(pool.Tick))
	if pool.Liquidity != nil {
		pool.Liquidity.FillBytes(buf[36:68])
	}
	if amountIn != nil {
		amountIn.FillBytes(buf[68:100])
	}
	if zeroForOne {
		buf[100] = 1
	}
	return buf
}

// =========================================================================
// Signed int256 encoding (two's complement, big-endian)
// =========================================================================

func encodeSigned256(dst []byte, v *big.Int) {
	if v == nil || v.Sign() == 0 {
		return // dst is already zeroed
	}
	if v.Sign() > 0 {
		v.FillBytes(dst)
		return
	}
	// Negative: two's complement = 2^256 + v
	tc := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), v)
	tc.FillBytes(dst)
}

// decodeSigned256 is defined in module.go
