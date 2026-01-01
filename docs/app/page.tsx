import Link from 'next/link';

const features = [
  {
    title: 'Cryptography',
    description: 'ML-DSA, ML-KEM, SLH-DSA, FROST, Ringtail, CGGMP21',
    href: '/docs/crypto',
    icon: '🔐',
  },
  {
    title: 'DEX',
    description: 'PoolManager, SwapRouter, Hooks, FlashLoan',
    href: '/docs/dex',
    icon: '🔄',
  },
  {
    title: 'FHE',
    description: 'Fully Homomorphic Encryption for private computation',
    href: '/docs/fhe',
    icon: '🔒',
  },
  {
    title: 'Oracle',
    description: 'Native price feeds and GraphQL via G-Chain',
    href: '/docs/oracle',
    icon: '📊',
  },
  {
    title: 'AI Mining',
    description: 'GPU attestation, NVTrust, compute rewards',
    href: '/docs/ai',
    icon: '🤖',
  },
  {
    title: 'Threshold',
    description: 'FROST Schnorr, CGGMP21 ECDSA, Ringtail PQ',
    href: '/docs/threshold',
    icon: '🔑',
  },
  {
    title: 'Bridge',
    description: 'Warp messaging, cross-chain verification',
    href: '/docs/bridge',
    icon: '🌉',
  },
  {
    title: 'ZK Proofs',
    description: 'KZG, Groth16, PLONK verification',
    href: '/docs/zk',
    icon: '✨',
  },
];

const standardLink = {
  title: 'Solidity Contracts',
  description: 'Pure Solidity implementations for maximum compatibility',
  href: 'https://standard.lux.network',
  external: true,
};

const stats = [
  { label: 'Precompiles', value: '40+' },
  { label: 'Gas Savings', value: '10-100x' },
  { label: 'Latency', value: '<3μs' },
  { label: 'Throughput', value: '400K/s' },
];

export default function Home() {
  return (
    <main className="min-h-screen">
      {/* Hero Section */}
      <section className="relative overflow-hidden bg-gradient-to-b from-fd-background to-fd-muted/30">
        <div className="absolute inset-0 bg-grid-white/[0.02] bg-[size:60px_60px]" />
        <div className="relative mx-auto max-w-7xl px-6 py-24 sm:py-32 lg:px-8">
          <div className="mx-auto max-w-2xl text-center">
            <div className="mb-8 flex justify-center">
              <div className="rounded-full bg-fd-primary/10 px-4 py-1.5 text-sm font-medium text-fd-primary ring-1 ring-inset ring-fd-primary/20">
                v0.4.0 — Native Performance
              </div>
            </div>
            <h1 className="text-4xl font-bold tracking-tight sm:text-6xl bg-gradient-to-r from-fd-foreground to-fd-foreground/70 bg-clip-text text-transparent">
              Lux Precompiles
            </h1>
            <p className="mt-6 text-lg leading-8 text-fd-muted-foreground">
              Native EVM precompiles for high-performance cryptography,
              DEX operations, and blockchain primitives.
              10-100x faster than Solidity.
            </p>
            <div className="mt-10 flex items-center justify-center gap-x-4">
              <Link
                href="/docs"
                className="rounded-lg bg-fd-primary px-5 py-2.5 text-sm font-semibold text-fd-primary-foreground shadow-sm hover:bg-fd-primary/90 transition-colors"
              >
                Get Started
              </Link>
              <Link
                href="https://github.com/luxfi/precompile"
                className="rounded-lg px-5 py-2.5 text-sm font-semibold text-fd-foreground ring-1 ring-fd-border hover:bg-fd-muted transition-colors"
              >
                GitHub →
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="border-y border-fd-border bg-fd-muted/30">
        <div className="mx-auto max-w-7xl px-6 py-12 lg:px-8">
          <dl className="grid grid-cols-2 gap-x-8 gap-y-8 text-center lg:grid-cols-4">
            {stats.map((stat) => (
              <div key={stat.label} className="mx-auto flex max-w-xs flex-col">
                <dt className="text-base leading-7 text-fd-muted-foreground">{stat.label}</dt>
                <dd className="order-first text-3xl font-semibold tracking-tight text-fd-foreground">{stat.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      {/* Features Grid */}
      <section className="mx-auto max-w-7xl px-6 py-24 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
            Native Performance for Every Operation
          </h2>
          <p className="mt-4 text-lg text-fd-muted-foreground">
            Precompiles execute as native code, bypassing EVM overhead
          </p>
        </div>
        <div className="mx-auto mt-16 grid max-w-5xl grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((feature) => (
            <Link
              key={feature.title}
              href={feature.href}
              className="group relative rounded-xl border border-fd-border bg-fd-card p-6 hover:border-fd-primary/50 hover:bg-fd-muted/50 transition-all"
            >
              <div className="text-3xl mb-4">{feature.icon}</div>
              <h3 className="text-lg font-semibold text-fd-foreground group-hover:text-fd-primary transition-colors">
                {feature.title}
              </h3>
              <p className="mt-2 text-sm text-fd-muted-foreground">
                {feature.description}
              </p>
            </Link>
          ))}
        </div>
      </section>

      {/* Standard Callout */}
      <section className="border-t border-fd-border">
        <div className="mx-auto max-w-7xl px-6 py-12 lg:px-8">
          <a
            href={standardLink.href}
            target="_blank"
            rel="noopener noreferrer"
            className="group flex items-center justify-between rounded-xl border border-fd-border bg-gradient-to-r from-fd-muted/50 to-fd-card p-6 hover:border-fd-primary/50 transition-all"
          >
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl">📜</span>
                <h3 className="text-lg font-semibold text-fd-foreground group-hover:text-fd-primary transition-colors">
                  {standardLink.title}
                </h3>
                <span className="rounded-full bg-fd-primary/10 px-2.5 py-0.5 text-xs font-medium text-fd-primary">
                  469 Contracts
                </span>
              </div>
              <p className="mt-2 text-sm text-fd-muted-foreground max-w-xl">
                Need portable Solidity? Lux Standard Library provides tokens, DeFi, governance, and more as pure Solidity.
              </p>
            </div>
            <span className="text-fd-muted-foreground group-hover:text-fd-primary transition-colors">→</span>
          </a>
        </div>
      </section>

      {/* Address Map Section */}
      <section className="border-t border-fd-border bg-fd-muted/30">
        <div className="mx-auto max-w-7xl px-6 py-24 lg:px-8">
          <div className="mx-auto max-w-2xl">
            <h2 className="text-2xl font-bold tracking-tight mb-8">Address Map</h2>
            <div className="rounded-xl border border-fd-border bg-fd-card overflow-hidden">
              <div className="border-b border-fd-border px-4 py-2 bg-fd-muted/50">
                <span className="text-sm text-fd-muted-foreground">Precompile Ranges</span>
              </div>
              <pre className="p-4 text-sm overflow-x-auto">
                <code className="text-fd-foreground">{`0x0100-0x01FF  Warp/Teleport    Cross-chain messaging
0x0300-0x03FF  AI/ML            Mining, NVTrust, Models
0x0400-0x04FF  DEX              Uniswap v4-style AMM
0x0500-0x05FF  Graph/Query      GraphQL, Subscriptions
0x0600-0x06FF  Post-Quantum     ML-DSA, ML-KEM, SLH-DSA
0x0700-0x07FF  Privacy          FHE, ECIES, Ring, HPKE
0x0800-0x08FF  Threshold        FROST, CGGMP21, Ringtail
0x0900-0x09FF  ZK Proofs        KZG, Groth16, PLONK`}</code>
              </pre>
            </div>
            <div className="mt-8 flex gap-4">
              <Link
                href="/docs"
                className="text-sm font-medium text-fd-primary hover:text-fd-primary/80"
              >
                View full address map →
              </Link>
              <Link
                href="/docs/usage"
                className="text-sm font-medium text-fd-muted-foreground hover:text-fd-foreground"
              >
                Usage examples
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Performance Section */}
      <section className="mx-auto max-w-7xl px-6 py-24 lg:px-8">
        <div className="mx-auto max-w-2xl text-center mb-16">
          <h2 className="text-3xl font-bold tracking-tight">Benchmarks (Apple M1 Max)</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          <div className="text-center">
            <div className="mx-auto w-12 h-12 rounded-full bg-fd-primary/10 flex items-center justify-center mb-4">
              <span className="text-2xl">🔄</span>
            </div>
            <h3 className="font-semibold mb-2">DEX Swap</h3>
            <p className="text-2xl font-bold text-fd-primary">2.26μs</p>
            <p className="text-sm text-fd-muted-foreground">443K ops/sec</p>
          </div>
          <div className="text-center">
            <div className="mx-auto w-12 h-12 rounded-full bg-fd-primary/10 flex items-center justify-center mb-4">
              <span className="text-2xl">🔐</span>
            </div>
            <h3 className="font-semibold mb-2">ML-DSA Verify</h3>
            <p className="text-2xl font-bold text-fd-primary">50μs</p>
            <p className="text-sm text-fd-muted-foreground">Post-quantum secure</p>
          </div>
          <div className="text-center">
            <div className="mx-auto w-12 h-12 rounded-full bg-fd-primary/10 flex items-center justify-center mb-4">
              <span className="text-2xl">🔑</span>
            </div>
            <h3 className="font-semibold mb-2">FROST Verify</h3>
            <p className="text-2xl font-bold text-fd-primary">45μs</p>
            <p className="text-sm text-fd-muted-foreground">Threshold Schnorr</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-fd-border">
        <div className="mx-auto max-w-7xl px-6 py-12 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-8">
            <div>
              <h4 className="text-sm font-semibold text-fd-foreground mb-4">Documentation</h4>
              <ul className="space-y-2">
                <li><Link href="https://docs.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Lux Docs</Link></li>
                <li><Link href="https://standard.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Standard Contracts</Link></li>
                <li><Link href="https://precompile.lux.network" className="text-sm text-fd-primary hover:text-fd-primary/80">Precompiles</Link></li>
                <li><Link href="https://lps.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">LPs (Proposals)</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-fd-foreground mb-4">Network</h4>
              <ul className="space-y-2">
                <li><Link href="https://consensus.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Consensus</Link></li>
                <li><Link href="https://explorer.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Explorer</Link></li>
                <li><Link href="https://bridge.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Bridge</Link></li>
                <li><Link href="https://dex.lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">DEX</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-fd-foreground mb-4">Developers</h4>
              <ul className="space-y-2">
                <li><Link href="https://github.com/luxfi" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">GitHub</Link></li>
                <li><Link href="https://github.com/luxfi/precompile" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Precompile Repo</Link></li>
                <li><Link href="https://github.com/luxfi/standard" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Standard Repo</Link></li>
                <li><Link href="https://github.com/luxfi/node" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Node Repo</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-fd-foreground mb-4">Community</h4>
              <ul className="space-y-2">
                <li><Link href="https://discord.gg/lux" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Discord</Link></li>
                <li><Link href="https://twitter.com/luxnetwork" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Twitter</Link></li>
                <li><Link href="https://t.me/luxnetwork" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Telegram</Link></li>
                <li><Link href="https://lux.network" className="text-sm text-fd-muted-foreground hover:text-fd-foreground">Website</Link></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-fd-border pt-8 flex flex-col items-center justify-between gap-4 sm:flex-row">
            <p className="text-sm text-fd-muted-foreground">
              © 2025 Lux Industries. MIT License.
            </p>
            <p className="text-sm text-fd-muted-foreground">
              Built with Fumadocs
            </p>
          </div>
        </div>
      </footer>
    </main>
  );
}
