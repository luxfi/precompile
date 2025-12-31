// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

// GraphQL Schema for Lux Standard Library + DEX
// This schema covers all deployed contracts from ~/work/lux/standard

const GraphQLSchema = `
# =============================================================================
# Core Types
# =============================================================================

type Query {
  # Chain queries
  chainInfo: ChainInfo!
  block(hash: String, number: Int): Block
  blocks(first: Int, skip: Int, orderBy: String, orderDirection: String): [Block!]!

  # Account queries
  account(address: String!): Account
  balance(address: String!): String!

  # DEX Factory & Bundle
  factory(id: String!): Factory
  bundle(id: String!): Bundle

  # Token queries
  token(id: String!): Token
  tokens(first: Int, skip: Int, orderBy: String, orderDirection: String, where: TokenFilter): [Token!]!
  tokenDayDatas(first: Int, where: TokenDayDataFilter): [TokenDayData!]!

  # Pool queries (V3)
  pool(id: String!): Pool
  pools(first: Int, skip: Int, orderBy: String, orderDirection: String, where: PoolFilter): [Pool!]!
  poolDayDatas(first: Int, where: PoolDayDataFilter): [PoolDayData!]!
  poolHourDatas(first: Int, where: PoolHourDataFilter): [PoolHourData!]!

  # Pair queries (V2)
  pair(id: String!): Pair
  pairs(first: Int, skip: Int, orderBy: String, orderDirection: String, where: PairFilter): [Pair!]!
  pairDayDatas(first: Int, where: PairDayDataFilter): [PairDayData!]!

  # Tick queries
  tick(id: String!): Tick
  ticks(first: Int, where: TickFilter): [Tick!]!

  # Position queries
  position(id: String!): Position
  positions(first: Int, where: PositionFilter): [Position!]!

  # Swap queries
  swap(id: String!): Swap
  swaps(first: Int, skip: Int, orderBy: String, orderDirection: String, where: SwapFilter): [Swap!]!

  # Mint/Burn queries
  mints(first: Int, where: MintFilter): [Mint!]!
  burns(first: Int, where: BurnFilter): [Burn!]!

  # ==========================================================================
  # OpenZeppelin Standard Library Queries
  # ==========================================================================

  # ERC20 queries
  erc20Contract(id: String!): ERC20Contract
  erc20Contracts(first: Int, where: ERC20Filter): [ERC20Contract!]!
  erc20Balances(first: Int, where: ERC20BalanceFilter): [ERC20Balance!]!
  erc20Transfers(first: Int, where: ERC20TransferFilter): [ERC20Transfer!]!

  # ERC721 queries
  erc721Contract(id: String!): ERC721Contract
  erc721Contracts(first: Int, where: ERC721Filter): [ERC721Contract!]!
  erc721Tokens(first: Int, where: ERC721TokenFilter): [ERC721Token!]!
  erc721Transfers(first: Int, where: ERC721TransferFilter): [ERC721Transfer!]!

  # ERC1155 queries
  erc1155Contract(id: String!): ERC1155Contract
  erc1155Contracts(first: Int, where: ERC1155Filter): [ERC1155Contract!]!
  erc1155Balances(first: Int, where: ERC1155BalanceFilter): [ERC1155Balance!]!
  erc1155Transfers(first: Int, where: ERC1155TransferFilter): [ERC1155Transfer!]!

  # Access Control queries
  accessControl(id: String!): AccessControl
  accessControls(first: Int): [AccessControl!]!
  roles(first: Int, where: RoleFilter): [Role!]!
  roleMembers(first: Int, where: RoleMemberFilter): [RoleMember!]!

  # Governor queries
  governor(id: String!): Governor
  governors(first: Int): [Governor!]!
  proposals(first: Int, where: ProposalFilter): [Proposal!]!
  votes(first: Int, where: VoteFilter): [Vote!]!

  # Timelock queries
  timelock(id: String!): Timelock
  timelocks(first: Int): [Timelock!]!
  timelockOperations(first: Int, where: TimelockOperationFilter): [TimelockOperation!]!

  # ==========================================================================
  # Lux-Specific Queries
  # ==========================================================================

  # Bridge tokens
  bridgeToken(id: String!): BridgeToken
  bridgeTokens(first: Int): [BridgeToken!]!
  bridgeTransfers(first: Int, where: BridgeTransferFilter): [BridgeTransfer!]!

  # Liquid (Self-repaying loans)
  liquidVault(id: String!): LiquidVault
  liquidVaults(first: Int): [LiquidVault!]!
  liquidPositions(first: Int, where: LiquidPositionFilter): [LiquidPosition!]!

  # Perpetuals
  perpMarket(id: String!): PerpMarket
  perpMarkets(first: Int): [PerpMarket!]!
  perpPositions(first: Int, where: PerpPositionFilter): [PerpPosition!]!

  # ==========================================================================
  # Cross-Chain Aggregation
  # ==========================================================================

  allChains: [ChainStats!]!
  crossChainSwaps(first: Int, where: CrossChainSwapFilter): [CrossChainSwap!]!
}

# =============================================================================
# Chain & Block Types
# =============================================================================

type ChainInfo {
  vmName: String!
  version: String!
  readOnly: Boolean!
  chainId: String!
  supportedChains: [String!]!
}

type Block {
  hash: String!
  number: Int!
  timestamp: Int!
  parentHash: String!
  gasUsed: String!
  gasLimit: String!
  transactions: [Transaction!]!
}

type Transaction {
  hash: String!
  from: String!
  to: String
  value: String!
  gasPrice: String!
  gasUsed: String!
  input: String!
  status: Int!
}

type Account {
  address: String!
  balance: String!
  nonce: Int!
  code: String
}

# =============================================================================
# DEX V3 Types
# =============================================================================

type Factory {
  id: String!
  poolCount: Int!
  pairCount: Int!
  txCount: String!
  totalVolumeUSD: String!
  totalVolumeETH: String!
  totalValueLockedUSD: String!
  totalValueLockedETH: String!
  totalFeesUSD: String!
  totalFeesETH: String!
  owner: String!
}

type Bundle {
  id: String!
  ethPriceUSD: String!
  luxPriceUSD: String!
}

type Token {
  id: String!
  symbol: String!
  name: String!
  decimals: Int!
  totalSupply: String!
  volume: String!
  volumeUSD: String!
  untrackedVolumeUSD: String!
  feesUSD: String!
  txCount: String!
  poolCount: Int!
  totalValueLocked: String!
  totalValueLockedUSD: String!
  totalValueLockedUSDUntracked: String!
  derivedETH: String!
  derivedLUX: String!
  whitelistPools: [Pool!]!
  tokenDayData: [TokenDayData!]!
}

type Pool {
  id: String!
  createdAtTimestamp: String!
  createdAtBlockNumber: String!
  token0: Token!
  token1: Token!
  feeTier: Int!
  liquidity: String!
  sqrtPrice: String!
  feeGrowthGlobal0X128: String!
  feeGrowthGlobal1X128: String!
  token0Price: String!
  token1Price: String!
  tick: Int
  observationIndex: String!
  volumeToken0: String!
  volumeToken1: String!
  volumeUSD: String!
  untrackedVolumeUSD: String!
  feesUSD: String!
  txCount: String!
  collectedFeesToken0: String!
  collectedFeesToken1: String!
  collectedFeesUSD: String!
  totalValueLockedToken0: String!
  totalValueLockedToken1: String!
  totalValueLockedETH: String!
  totalValueLockedUSD: String!
  totalValueLockedUSDUntracked: String!
  liquidityProviderCount: String!
  poolHourData: [PoolHourData!]!
  poolDayData: [PoolDayData!]!
  mints: [Mint!]!
  burns: [Burn!]!
  swaps: [Swap!]!
  ticks: [Tick!]!
}

type Tick {
  id: String!
  poolAddress: String
  tickIdx: Int!
  pool: Pool!
  liquidityGross: String!
  liquidityNet: String!
  price0: String!
  price1: String!
  volumeToken0: String!
  volumeToken1: String!
  volumeUSD: String!
  untrackedVolumeUSD: String!
  feesUSD: String!
  collectedFeesToken0: String!
  collectedFeesToken1: String!
  collectedFeesUSD: String!
  createdAtTimestamp: String!
  createdAtBlockNumber: String!
  liquidityProviderCount: String!
  feeGrowthOutside0X128: String!
  feeGrowthOutside1X128: String!
}

type Position {
  id: String!
  owner: String!
  pool: Pool!
  token0: Token!
  token1: Token!
  tickLower: Tick!
  tickUpper: Tick!
  liquidity: String!
  depositedToken0: String!
  depositedToken1: String!
  withdrawnToken0: String!
  withdrawnToken1: String!
  collectedToken0: String!
  collectedToken1: String!
  collectedFeesToken0: String!
  collectedFeesToken1: String!
  transaction: Transaction!
  feeGrowthInside0LastX128: String!
  feeGrowthInside1LastX128: String!
}

type Swap {
  id: String!
  transaction: Transaction!
  timestamp: String!
  pool: Pool!
  token0: Token!
  token1: Token!
  sender: String!
  recipient: String!
  origin: String!
  amount0: String!
  amount1: String!
  amountUSD: String!
  sqrtPriceX96: String!
  tick: Int!
  logIndex: Int
}

type Mint {
  id: String!
  transaction: Transaction!
  timestamp: String!
  pool: Pool!
  token0: Token!
  token1: Token!
  owner: String!
  sender: String
  origin: String!
  amount: String!
  amount0: String!
  amount1: String!
  amountUSD: String
  tickLower: Int!
  tickUpper: Int!
  logIndex: Int
}

type Burn {
  id: String!
  transaction: Transaction!
  timestamp: String!
  pool: Pool!
  token0: Token!
  token1: Token!
  owner: String
  origin: String!
  amount: String!
  amount0: String!
  amount1: String!
  amountUSD: String
  tickLower: Int!
  tickUpper: Int!
  logIndex: Int
}

# =============================================================================
# DEX V2 Types
# =============================================================================

type Pair {
  id: String!
  token0: Token!
  token1: Token!
  reserve0: String!
  reserve1: String!
  totalSupply: String!
  reserveETH: String!
  reserveUSD: String!
  trackedReserveETH: String!
  token0Price: String!
  token1Price: String!
  volumeToken0: String!
  volumeToken1: String!
  volumeUSD: String!
  untrackedVolumeUSD: String!
  txCount: String!
  createdAtTimestamp: String!
  createdAtBlockNumber: String!
  liquidityProviderCount: String!
  pairHourData: [PairHourData!]!
  pairDayData: [PairDayData!]!
}

# =============================================================================
# Time Series Types
# =============================================================================

type TokenDayData {
  id: String!
  date: Int!
  token: Token!
  volume: String!
  volumeUSD: String!
  untrackedVolumeUSD: String!
  totalValueLocked: String!
  totalValueLockedUSD: String!
  priceUSD: String!
  feesUSD: String!
  open: String!
  high: String!
  low: String!
  close: String!
}

type PoolDayData {
  id: String!
  date: Int!
  pool: Pool!
  liquidity: String!
  sqrtPrice: String!
  token0Price: String!
  token1Price: String!
  tick: Int
  feeGrowthGlobal0X128: String!
  feeGrowthGlobal1X128: String!
  tvlUSD: String!
  volumeToken0: String!
  volumeToken1: String!
  volumeUSD: String!
  feesUSD: String!
  txCount: String!
  open: String!
  high: String!
  low: String!
  close: String!
}

type PoolHourData {
  id: String!
  periodStartUnix: Int!
  pool: Pool!
  liquidity: String!
  sqrtPrice: String!
  token0Price: String!
  token1Price: String!
  tick: Int
  feeGrowthGlobal0X128: String!
  feeGrowthGlobal1X128: String!
  tvlUSD: String!
  volumeToken0: String!
  volumeToken1: String!
  volumeUSD: String!
  feesUSD: String!
  txCount: String!
  open: String!
  high: String!
  low: String!
  close: String!
}

type PairDayData {
  id: String!
  date: Int!
  pair: Pair!
  reserve0: String!
  reserve1: String!
  reserveUSD: String!
  dailyVolumeToken0: String!
  dailyVolumeToken1: String!
  dailyVolumeUSD: String!
  dailyTxns: String!
}

type PairHourData {
  id: String!
  periodStartUnix: Int!
  pair: Pair!
  reserve0: String!
  reserve1: String!
  reserveUSD: String!
  hourlyVolumeToken0: String!
  hourlyVolumeToken1: String!
  hourlyVolumeUSD: String!
  hourlyTxns: String!
}

# =============================================================================
# OpenZeppelin ERC20 Types
# =============================================================================

type ERC20Contract {
  id: String!
  name: String
  symbol: String
  decimals: Int!
  totalSupply: String!
  holders: Int!
  transfers: Int!
  asAccount: Account
}

type ERC20Balance {
  id: String!
  contract: ERC20Contract!
  account: Account!
  value: String!
  valueExact: String!
}

type ERC20Transfer {
  id: String!
  contract: ERC20Contract!
  from: Account!
  to: Account!
  value: String!
  valueExact: String!
  timestamp: Int!
  transaction: Transaction!
}

# =============================================================================
# OpenZeppelin ERC721 Types
# =============================================================================

type ERC721Contract {
  id: String!
  name: String
  symbol: String
  totalSupply: String!
  tokens: [ERC721Token!]!
  asAccount: Account
}

type ERC721Token {
  id: String!
  contract: ERC721Contract!
  identifier: String!
  owner: Account!
  uri: String
  approval: Account
  transfers: [ERC721Transfer!]!
}

type ERC721Transfer {
  id: String!
  contract: ERC721Contract!
  token: ERC721Token!
  from: Account!
  to: Account!
  timestamp: Int!
  transaction: Transaction!
}

# =============================================================================
# OpenZeppelin ERC1155 Types
# =============================================================================

type ERC1155Contract {
  id: String!
  totalSupply: String!
  asAccount: Account
}

type ERC1155Balance {
  id: String!
  contract: ERC1155Contract!
  token: ERC1155Token!
  account: Account!
  value: String!
  valueExact: String!
}

type ERC1155Token {
  id: String!
  contract: ERC1155Contract!
  identifier: String!
  uri: String
  totalSupply: String!
  balances: [ERC1155Balance!]!
}

type ERC1155Transfer {
  id: String!
  contract: ERC1155Contract!
  token: ERC1155Token!
  operator: Account!
  from: Account!
  to: Account!
  value: String!
  valueExact: String!
  timestamp: Int!
  transaction: Transaction!
}

# =============================================================================
# OpenZeppelin Access Control Types
# =============================================================================

type AccessControl {
  id: String!
  asAccount: Account
  roles: [Role!]!
}

type Role {
  id: String!
  contract: AccessControl!
  role: String!
  admin: Role
  adminOf: [Role!]!
  members: [RoleMember!]!
}

type RoleMember {
  id: String!
  role: Role!
  account: Account!
}

# =============================================================================
# OpenZeppelin Governor Types
# =============================================================================

type Governor {
  id: String!
  asAccount: Account
  name: String
  votingDelay: String!
  votingPeriod: String!
  proposalThreshold: String!
  quorum: String!
  proposals: [Proposal!]!
}

type Proposal {
  id: String!
  governor: Governor!
  proposalId: String!
  proposer: Account!
  startBlock: String!
  endBlock: String!
  description: String!
  state: ProposalState!
  eta: String
  forVotes: String!
  againstVotes: String!
  abstainVotes: String!
  votes: [Vote!]!
  calls: [ProposalCall!]!
}

enum ProposalState {
  Pending
  Active
  Canceled
  Defeated
  Succeeded
  Queued
  Expired
  Executed
}

type ProposalCall {
  id: String!
  proposal: Proposal!
  index: Int!
  target: Account!
  value: String!
  signature: String!
  calldata: String!
}

type Vote {
  id: String!
  proposal: Proposal!
  voter: Account!
  support: VoteSupport!
  weight: String!
  reason: String
  timestamp: Int!
  transaction: Transaction!
}

enum VoteSupport {
  Against
  For
  Abstain
}

# =============================================================================
# OpenZeppelin Timelock Types
# =============================================================================

type Timelock {
  id: String!
  asAccount: Account
  minDelay: String!
  operations: [TimelockOperation!]!
}

type TimelockOperation {
  id: String!
  timelock: Timelock!
  operationId: String!
  status: TimelockOperationStatus!
  delay: String!
  timestamp: String
  predecessor: TimelockOperation
  calls: [TimelockCall!]!
}

enum TimelockOperationStatus {
  Scheduled
  Executed
  Canceled
}

type TimelockCall {
  id: String!
  operation: TimelockOperation!
  index: Int!
  target: Account!
  value: String!
  data: String!
}

# =============================================================================
# Lux Bridge Types
# =============================================================================

type BridgeToken {
  id: String!
  symbol: String!
  name: String!
  decimals: Int!
  originalChain: String!
  originalAddress: String!
  totalBridged: String!
  totalMinted: String!
  totalBurned: String!
}

type BridgeTransfer {
  id: String!
  token: BridgeToken!
  from: Account!
  to: Account!
  amount: String!
  sourceChain: String!
  destChain: String!
  status: BridgeStatus!
  timestamp: Int!
  sourceTxHash: String!
  destTxHash: String
}

enum BridgeStatus {
  Pending
  Confirmed
  Completed
  Failed
}

# =============================================================================
# Liquid (Self-repaying Loans) Types
# =============================================================================

type LiquidVault {
  id: String!
  collateralToken: Token!
  debtToken: Token!
  syntheticToken: Token!
  totalCollateral: String!
  totalDebt: String!
  totalSynthetic: String!
  collateralRatio: String!
  yieldRate: String!
  positions: [LiquidPosition!]!
}

type LiquidPosition {
  id: String!
  vault: LiquidVault!
  owner: Account!
  collateral: String!
  debt: String!
  synthetic: String!
  lastHarvest: Int!
  healthFactor: String!
}

# =============================================================================
# Perpetuals Types
# =============================================================================

type PerpMarket {
  id: String!
  indexToken: Token!
  longToken: Token!
  shortToken: Token!
  isLong: Boolean!
  openInterest: String!
  maxOpenInterest: String!
  fundingRate: String!
  borrowingRate: String!
  positions: [PerpPosition!]!
}

type PerpPosition {
  id: String!
  market: PerpMarket!
  account: Account!
  collateralToken: Token!
  isLong: Boolean!
  sizeInUsd: String!
  sizeInTokens: String!
  collateralAmount: String!
  averagePrice: String!
  entryFundingRate: String!
  realizedPnl: String!
  lastUpdated: Int!
}

# =============================================================================
# Cross-Chain Types
# =============================================================================

type ChainStats {
  chainId: String!
  chainName: String!
  tvlUSD: String!
  volumeUSD24h: String!
  poolCount: Int!
  tokenCount: Int!
  txCount24h: Int!
}

type CrossChainSwap {
  id: String!
  sourceChain: String!
  destChain: String!
  sender: String!
  recipient: String!
  tokenIn: Token!
  tokenOut: Token!
  amountIn: String!
  amountOut: String!
  amountUSD: String!
  status: CrossChainSwapStatus!
  timestamp: Int!
  sourceTxHash: String!
  destTxHash: String
}

enum CrossChainSwapStatus {
  Initiated
  Bridging
  Completed
  Failed
}

# =============================================================================
# Filter Input Types
# =============================================================================

input TokenFilter {
  id: String
  symbol: String
  symbol_contains: String
  name_contains: String
  volumeUSD_gt: String
  totalValueLockedUSD_gt: String
}

input PoolFilter {
  id: String
  token0: String
  token1: String
  feeTier: Int
  liquidity_gt: String
  volumeUSD_gt: String
  totalValueLockedUSD_gt: String
}

input PairFilter {
  id: String
  token0: String
  token1: String
  reserveUSD_gt: String
  volumeUSD_gt: String
}

input TickFilter {
  pool: String
  tickIdx: Int
  tickIdx_gte: Int
  tickIdx_lte: Int
}

input PositionFilter {
  owner: String
  pool: String
  liquidity_gt: String
}

input SwapFilter {
  pool: String
  token0: String
  token1: String
  sender: String
  recipient: String
  timestamp_gt: Int
  timestamp_lt: Int
  amountUSD_gt: String
}

input MintFilter {
  pool: String
  owner: String
  timestamp_gt: Int
}

input BurnFilter {
  pool: String
  owner: String
  timestamp_gt: Int
}

input TokenDayDataFilter {
  token: String
  date_gt: Int
  date_lt: Int
}

input PoolDayDataFilter {
  pool: String
  date_gt: Int
  date_lt: Int
}

input PoolHourDataFilter {
  pool: String
  periodStartUnix_gt: Int
  periodStartUnix_lt: Int
}

input PairDayDataFilter {
  pair: String
  date_gt: Int
  date_lt: Int
}

input ERC20Filter {
  symbol: String
  name_contains: String
}

input ERC20BalanceFilter {
  contract: String
  account: String
  value_gt: String
}

input ERC20TransferFilter {
  contract: String
  from: String
  to: String
  timestamp_gt: Int
}

input ERC721Filter {
  symbol: String
  name_contains: String
}

input ERC721TokenFilter {
  contract: String
  owner: String
}

input ERC721TransferFilter {
  contract: String
  from: String
  to: String
  timestamp_gt: Int
}

input ERC1155Filter {
  id: String
}

input ERC1155BalanceFilter {
  contract: String
  account: String
}

input ERC1155TransferFilter {
  contract: String
  from: String
  to: String
  timestamp_gt: Int
}

input RoleFilter {
  contract: String
  role: String
}

input RoleMemberFilter {
  role: String
  account: String
}

input ProposalFilter {
  governor: String
  proposer: String
  state: ProposalState
}

input VoteFilter {
  proposal: String
  voter: String
  support: VoteSupport
}

input TimelockOperationFilter {
  timelock: String
  status: TimelockOperationStatus
}

input BridgeTransferFilter {
  token: String
  from: String
  to: String
  sourceChain: String
  destChain: String
  status: BridgeStatus
}

input LiquidPositionFilter {
  vault: String
  owner: String
}

input PerpPositionFilter {
  market: String
  account: String
  isLong: Boolean
}

input CrossChainSwapFilter {
  sourceChain: String
  destChain: String
  sender: String
  status: CrossChainSwapStatus
}
`
