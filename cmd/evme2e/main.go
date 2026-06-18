// Command evme2e is the PATH-A (EVM 0x9010) e2e driver: it sends REAL signed
// C-Chain transactions to the V4 PoolManager precompile at
// 0x0000000000000000000000000000000000009010 and proves the call ROUTES through
// NewZAPEngine -> the venue D-Chain -> consensus fills -> a V4 BalanceDelta +
// native settlement.
//
// It encodes the three V4 calls with the precompile's own ABI encoders
// (dex.EncodePoolKeyABI etc. — byte-identical to what the on-chain decoder
// expects):
//
//	initialize((c0,c1,fee,tickSpacing,hooks), sqrtPriceX96)            sel 0x6276CBBE
//	modifyLiquidity(key,(tickLower,tickUpper,liqDelta,salt),hookData)  sel 0x5A6BCFDA
//	swap(key,(zeroForOne,amountSpecified,sqrtPriceLimitX96),hookData)  sel 0xF3CD914C
//
// It also opens a direct ZAP connection to the same venue to OBSERVE the resting
// book (clob_depth) before/after each EVM call — the routing proof: liquidity
// the EVM precompile placed/consumed shows up on the venue under the exact
// keccak256(PoolKey) poolId.
//
// Funding is a localnet genesis account derived from the well-known LightMnemonic
// dev seed (m/44'/60'/0'/0/0) — NOT an EWOQ key.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"time"

	dex "github.com/luxfi/precompile/dex"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/ethclient"
	"github.com/luxfi/rpc"
)

var lxpool = common.HexToAddress("0x0000000000000000000000000000000000009010")

const (
	selInitialize      = 0x6276CBBE
	selModifyLiquidity = 0x5A6BCFDA
	selSwap            = 0xF3CD914C
)

func sel(s uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, s); return b }

func i256(v *big.Int) []byte {
	out := make([]byte, 32)
	if v.Sign() >= 0 {
		v.FillBytes(out)
		return out
	}
	new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), v).FillBytes(out)
	return out
}
func u256(v *big.Int) []byte { out := make([]byte, 32); v.FillBytes(out); return out }
func boolWord(b bool) []byte {
	out := make([]byte, 32)
	if b {
		out[31] = 1
	}
	return out
}

// sqrtPriceX96 = floor(sqrt(price) * 2^96).
func sqrtPriceX96(price float64) *big.Int {
	q96 := new(big.Float).SetPrec(256)
	q96.SetInt(new(big.Int).Lsh(big.NewInt(1), 96))
	sp := new(big.Float).SetPrec(256).Sqrt(big.NewFloat(price))
	sp.Mul(sp, q96)
	r, _ := sp.Int(nil)
	return r
}

func key(c0, c1 common.Address, fee uint32, ts int32) dex.PoolKey {
	return dex.PoolKey{
		Currency0: dex.Currency{Address: c0}, Currency1: dex.Currency{Address: c1},
		Fee: fee, TickSpacing: ts, Hooks: common.Address{},
	}
}

func encInitialize(k dex.PoolKey, sqrtP *big.Int) []byte {
	return append(append(sel(selInitialize), dex.EncodePoolKeyABI(k)...), u256(sqrtP)...)
}
func encModifyLiquidity(k dex.PoolKey, tickLower, tickUpper int32, liqDelta *big.Int, salt [32]byte) []byte {
	out := append(sel(selModifyLiquidity), dex.EncodePoolKeyABI(k)...)
	out = append(out, i256(big.NewInt(int64(tickLower)))...)
	out = append(out, i256(big.NewInt(int64(tickUpper)))...)
	out = append(out, i256(liqDelta)...)
	out = append(out, salt[:]...)
	return out
}
func encSwap(k dex.PoolKey, zeroForOne bool, amt, sqrtLimit *big.Int) []byte {
	out := append(sel(selSwap), dex.EncodePoolKeyABI(k)...)
	out = append(out, boolWord(zeroForOne)...)
	out = append(out, i256(amt)...)
	out = append(out, u256(sqrtLimit)...)
	return out
}

func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:9650/ext/bc/C/rpc", "C-Chain RPC")
	venueAddr := flag.String("venue", "127.0.0.1:9099", "venue ZAP addr (for book observation)")
	pkHex := flag.String("pk", "ed0c0416e953639c0ae02e313c2c73a84dd509937e64330b303342d16af7394e", "funded genesis privkey hex (LightMnemonic idx0)")
	flag.Parse()

	ctx := context.Background()
	cl, err := ethclient.Dial(*rpcURL)
	must("dial", err)
	chainID, err := cl.ChainID(ctx)
	must("chainID", err)
	pk, err := crypto.HexToECDSA(*pkHex)
	must("key", err)
	from := common.BytesToAddress(crypto.PubkeyToAddress(pk.PublicKey).Bytes())
	fmt.Printf("PATH-A driver  rpc=%s chainID=%s from=%s\n", *rpcURL, chainID, from.Hex())

	// Venue observation channel (read-only clob_depth on the same poolId).
	vctx, vcancel := context.WithTimeout(ctx, 90*time.Second)
	defer vcancel()
	vconn, verr := rpc.ZAPDial(vctx, *venueAddr)
	if verr != nil {
		fmt.Printf("WARN venue dial (%s): %v — book observation disabled\n", *venueAddr, verr)
	}

	c0 := common.Address{}                                                   // native LUX
	c1 := common.HexToAddress("0x0000000000000000000000000000000000000042") // currency1
	const fee = uint32(3000)
	const ts = int32(60)
	k := key(c0, c1, fee, ts)
	poolID := k.ID()
	fmt.Printf("pool c0=%s c1=%s fee=%d tickSpacing=%d\npoolID(keccak256(PoolKey))=0x%s\n",
		c0.Hex(), c1.Hex(), fee, ts, hex.EncodeToString(poolID[:]))

	depth := func(tag string) {
		if vconn == nil {
			return
		}
		r, e := vconn.Call(vctx, "clob_depth", poolID[:])
		if e != nil || len(r) < 29 {
			fmt.Printf("  VENUE %-12s depth err: %v\n", tag, e)
			return
		}
		fmt.Printf("  VENUE %-12s orders=%d remaining=%.3f bestBid=%.4f bestAsk=%.4f found=%v\n",
			tag, binary.BigEndian.Uint32(r[0:4]), math.Float64frombits(binary.BigEndian.Uint64(r[4:12])),
			math.Float64frombits(binary.BigEndian.Uint64(r[12:20])), math.Float64frombits(binary.BigEndian.Uint64(r[20:28])), r[28] == 1)
	}

	send := func(label string, data []byte) *types.Receipt {
		nonce, e := cl.PendingNonceAt(ctx, from)
		must(label+" nonce", e)
		gp, e := cl.SuggestGasPrice(ctx)
		must(label+" gasprice", e)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gp, Gas: 5_000_000, To: &lxpool, Value: big.NewInt(0), Data: data})
		signed, e := types.SignTx(tx, types.LatestSignerForChainID(chainID), pk)
		must(label+" sign", e)
		if e := cl.SendTransaction(ctx, signed); e != nil {
			fmt.Printf("  %-16s SEND ERROR: %v\n", label, e)
			return nil
		}
		h := signed.Hash()
		r := waitReceipt(ctx, cl, h)
		if r == nil {
			fmt.Printf("  %-16s tx=%s NO RECEIPT\n", label, h.Hex())
			return nil
		}
		st := "SUCCESS"
		if r.Status == 0 {
			st = "REVERT"
		}
		fmt.Printf("  %-16s tx=%s status=%d(%s) block=%d gasUsed=%d\n", label, h.Hex(), r.Status, st, r.BlockNumber.Uint64(), r.GasUsed)
		return r
	}

	bal := func(tag string) {
		b, _ := cl.BalanceAt(ctx, from, nil)
		pm, _ := cl.BalanceAt(ctx, lxpool, nil)
		fmt.Printf("  BAL %-12s from=%s poolMgr=%s\n", tag, b.String(), pm.String())
	}

	// ---- STEP 1: initialize price=100 -> clob_ensure_market on venue ----
	fmt.Println("\n--- STEP 1: initialize(price=100) -> clob_ensure_market ---")
	depth("pre-init")
	send("initialize", encInitialize(k, sqrtPriceX96(100)))
	depth("post-init")

	// ---- STEP 2: modifyLiquidity (+) -> clob_place a resting ASK ----
	// init price=100 (tick 46054). Place an ASK just above: tick 46554 (~price 105).
	// An ask funds base=currency0=native LUX (clean settlement).
	fmt.Println("\n--- STEP 2: modifyLiquidity(+10 @ ask~105) -> clob_place ---")
	bal("pre-place")
	var salt [32]byte
	salt[31] = 1
	send("modifyLiq-ask", encModifyLiquidity(k, 46500, 46560, big.NewInt(10), salt))
	bal("post-place")
	depth("post-place")

	// ---- STEP 3: swap marketable SELL crossing... need a BID to cross a sell ----
	// Place a resting BID just below init: tick 45600 (~price 96), funds quote=c1.
	// (LP needs c1 for the bid; if c1 settlement is unfunded this place may revert —
	//  reported honestly. The ASK above is the native-clean leg.)
	fmt.Println("\n--- STEP 3: modifyLiquidity(+8 @ bid~96) -> clob_place ---")
	var salt2 [32]byte
	salt2[31] = 2
	send("modifyLiq-bid", encModifyLiquidity(k, 45540, 45600, big.NewInt(8), salt2))
	depth("post-place-bid")

	// ---- STEP 4: swap marketable BUY (cross the ASK) -> clob_submit -> fills ----
	// !zeroForOne buy: taker RECEIVES base=native (credit, clean), OWES quote=c1.
	fmt.Println("\n--- STEP 4: swap BUY 5 (cross ask) -> clob_submit -> fills+BalanceDelta ---")
	bal("pre-swap-buy")
	depth("pre-swap-buy")
	maxSqrt := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	send("swap-buy", encSwap(k, false, big.NewInt(-5), maxSqrt))
	bal("post-swap-buy")
	depth("post-swap-buy")

	// ---- STEP 5: swap marketable SELL (cross the BID) -> owed leg = native ----
	// zeroForOne sell: taker OWES base=native (clean SubBalance), RECEIVES quote=c1.
	fmt.Println("\n--- STEP 5: swap SELL 4 (cross bid) -> clob_submit -> fills (native owed) ---")
	bal("pre-swap-sell")
	depth("pre-swap-sell")
	minSqrt := big.NewInt(1)
	send("swap-sell", encSwap(k, true, big.NewInt(-4), minSqrt))
	bal("post-swap-sell")
	depth("post-swap-sell")

	fmt.Println("\nPATH-A complete. VENUE depth deltas under poolID = routing proof;")
	fmt.Println("BAL deltas (native currency0) = on-chain settlement proof.")
	if vconn != nil {
		_ = vconn.Close()
	}
}

func waitReceipt(ctx context.Context, cl *ethclient.Client, h common.Hash) *types.Receipt {
	dl := time.Now().Add(20 * time.Second)
	for time.Now().Before(dl) {
		r, err := cl.TransactionReceipt(ctx, h)
		if err == nil && r != nil {
			return r
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}
func must(stage string, err error) {
	if err != nil {
		fmt.Printf("FATAL %s: %v\n", stage, err)
		os.Exit(1)
	}
}
