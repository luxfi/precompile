// dex_clob_zap_test exercises the LIVE precompile <-> luxfi/dex CLOB path:
// the production dex.ZAPEngine adapter, driven through the public dex.PoolManager
// surface, talks over ZAP to a REAL github.com/luxfi/dex CLOB server backed by
// the real lx.OrderBook matcher (the d-chain gateway).
//
// This is the cross-repo integration peer of the in-module fake-listener tests
// in precompile/dex/engine_zap_conservation_test.go. It lives HERE (e2e module)
// because importing the real luxfi/dex server requires a `replace` for the local
// checkout — a legitimate test-harness concern in the e2e module, kept OUT of
// the public precompile module so that stays a pure-Go leaf with no venue-engine
// edge.
//
// Precompiles exercised: DEX (LP-9010, V4 = CLOB facade).
//
// This test lives in its OWN package (e2e/clob, not e2e/scenarios) so it
// compiles and runs independently of unrelated scenario tests.
package clob

import (
	"context"
	"math"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/holiman/uint256"
	dexapi "github.com/luxfi/dex/pkg/api"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/dex"
	"github.com/luxfi/rpc"
	"github.com/stretchr/testify/require"
)

// clobStateDB is a minimal in-memory implementation of the EXPORTED dex.StateDB
// interface, sufficient to drive PoolManager.{Initialize,ModifyLiquidity,Swap}.
// The CLOB path keeps no canonical state in the precompile, so this only needs
// to be a coherent scratch store.
type clobStateDB struct {
	mu       sync.Mutex
	state    map[common.Address]map[common.Hash]common.Hash
	balances map[common.Address]*uint256.Int
	exists   map[common.Address]bool
}

func newCLOBStateDB() *clobStateDB {
	return &clobStateDB{
		state:    make(map[common.Address]map[common.Hash]common.Hash),
		balances: make(map[common.Address]*uint256.Int),
		exists:   make(map[common.Address]bool),
	}
}

func (m *clobStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.state[addr]; ok {
		return s[key]
	}
	return common.Hash{}
}

func (m *clobStateDB) SetState(addr common.Address, key, value common.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state[addr] == nil {
		m.state[addr] = make(map[common.Hash]common.Hash)
	}
	m.state[addr][key] = value
}

func (m *clobStateDB) GetBalance(addr common.Address) *uint256.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.balances[addr]; ok {
		return b.Clone()
	}
	return uint256.NewInt(0)
}

func (m *clobStateDB) AddBalance(addr common.Address, amount *uint256.Int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.balances[addr] == nil {
		m.balances[addr] = uint256.NewInt(0)
	}
	m.balances[addr].Add(m.balances[addr], amount)
}

func (m *clobStateDB) SubBalance(addr common.Address, amount *uint256.Int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.balances[addr] == nil {
		m.balances[addr] = uint256.NewInt(0)
	}
	m.balances[addr].Sub(m.balances[addr], amount)
}

func (m *clobStateDB) Exist(addr common.Address) bool { return m.exists[addr] }
func (m *clobStateDB) CreateAccount(addr common.Address) {
	m.mu.Lock()
	m.exists[addr] = true
	m.mu.Unlock()
}
func (m *clobStateDB) GetBlockNumber() uint64 { return 1 }
func (m *clobStateDB) AddLog(_ *ethtypes.Log) {}

// startRealCLOBServer stands up a REAL luxfi/dex ZAP CLOB server (the d-chain
// gateway) and returns its address.
func startRealCLOBServer(t *testing.T) (addr string, srv *dexapi.ZAPServer) {
	t.Helper()
	listener, err := rpc.Listen("127.0.0.1:0")
	require.NoError(t, err, "listen")
	srv = dexapi.NewZAPServer(nil, "", nil)
	require.NoError(t, dexapi.RegisterCLOB(listener, srv), "register clob")

	addr = listener.Addr()
	ctx := context.Background()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = listener.Serve(ctx)
	}()

	// Readiness probe: a read-only cancel on a throwaway market id returns
	// "unknown market" once the server is accepting and creates nothing.
	deadline := time.Now().Add(2 * time.Second)
	probe := make([]byte, 40)
	probe[0] = 0xFF
	for time.Now().Before(deadline) {
		if c, derr := rpc.ZAPDial(ctx, addr); derr == nil {
			if _, perr := c.Call(ctx, dexapi.CLOBMethodCancel, probe); perr == nil {
				c.Close()
				break
			}
			c.Close()
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Cleanup(func() {
		_ = listener.Close()
		<-served
	})
	return addr, srv
}

func luxLUSDPoolKey() dex.PoolKey {
	return dex.PoolKey{
		Currency0:   dex.NativeCurrency,
		Currency1:   dex.Currency{Address: common.HexToAddress("0x000000000000000000000000000000000000C0DE")},
		Fee:         dex.Fee030,
		TickSpacing: dex.TickSpacing030,
		Hooks:       common.Address{},
	}
}

func snapTick(t *testing.T, want float64) int24Alias {
	t.Helper()
	raw := int(math.Log(want)/math.Log(1.0001) + 0.5)
	spacing := int(dex.TickSpacing030)
	return int24Alias((raw / spacing) * spacing)
}

// int24Alias mirrors dex.int24 (an int32) for local tick arithmetic.
type int24Alias = int32

func quantize8(p float64) float64 { return float64(int64(p*1e8)) / 1e8 }

func roundToBig(f float64) *big.Int {
	bf := new(big.Float).SetFloat64(math.Round(f))
	i, _ := bf.Int(nil)
	return i
}

// TestDEXCLOB_ZAPAgainstRealServer drives the production ZAPEngine through the
// PoolManager against a real luxfi/dex CLOB and asserts fills + value
// conservation across counterparties on the live matcher.
func TestDEXCLOB_ZAPAgainstRealServer(t *testing.T) {
	addr, srv := startRealCLOBServer(t)

	zap := dex.NewZAPEngine(addr, 2*time.Second)
	defer zap.Close()
	require.Equal(t, "DEX", zap.Brand(), "CLOB path advertises the brand-free fallback")

	pm := dex.NewPoolManager(zap)
	stateDB := newCLOBStateDB()
	key := luxLUSDPoolKey()
	poolId := key.ID()
	lp := common.HexToAddress("0x2222222222222222222222222222222222222222")
	taker := common.HexToAddress("0x1111111111111111111111111111111111111111")

	tick, err := pm.Initialize(stateDB, key, new(big.Int).Set(dex.Q96), nil)
	require.NoError(t, err, "Initialize")
	require.Equal(t, int24Alias(0), tick, "tick at price 1.0")
	require.Equal(t, 1, srv.MarketCount(), "server canonical markets")

	// Rest an ask above mid.
	askTick := snapTick(t, 2.0)
	askPrice, err := dexPriceForTick(askTick)
	require.NoError(t, err)
	askDelta, _, err := pm.ModifyLiquidity(stateDB, lp, key, dex.ModifyLiquidityParams{
		TickLower:      askTick,
		TickUpper:      askTick + dex.TickSpacing030,
		LiquidityDelta: big.NewInt(100),
	}, nil)
	require.NoError(t, err, "ModifyLiquidity ask")
	require.Truef(t, askDelta.Amount0.Sign() > 0 && askDelta.Amount1.Sign() == 0,
		"resting ask delta = (%s,%s), want (+base,0)", askDelta.Amount0, askDelta.Amount1)

	bestBid, bestAsk, ok := srv.BestBidAsk(poolId)
	require.True(t, ok, "server market exists")
	require.Equal(t, quantize8(askPrice), bestAsk, "server best ask = resting price")
	_ = bestBid

	// Marketable buy of 40 base, unbounded.
	const takeBase = int64(40)
	delta, err := pm.Swap(stateDB, taker, key, dex.SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-takeBase),
		SqrtPriceLimitX96: dex.MaxSqrtRatio,
	}, nil)
	require.NoError(t, err, "Swap")

	require.Equal(t, big.NewInt(-takeBase), delta.Amount0, "buy base = exactly taken")
	wantQuote := roundToBig(askPrice * float64(takeBase))
	require.Equal(t, wantQuote, delta.Amount1, "buy quote = base*askPrice from fills")

	// Cross-counterparty conservation.
	makerRealized := dex.NewBalanceDelta(big.NewInt(takeBase), new(big.Int).Neg(wantQuote))
	require.True(t, delta.Add(makerRealized).IsZero(), "value conserved across taker+maker")
}

// dexPriceForTick recomputes the float CLOB price for a tick using the exported
// V4 TickMath so the test agrees with the adapter's resting price exactly.
func dexPriceForTick(tick int24Alias) (float64, error) {
	sqrtRatio, err := dex.GetSqrtRatioAtTick(tick)
	if err != nil {
		return 0, err
	}
	sp, _ := new(big.Float).SetInt(sqrtRatio).Float64()
	q96 := math.Ldexp(1, 96)
	r := sp / q96
	return r * r, nil
}
