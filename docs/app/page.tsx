import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-8">
      <div className="max-w-4xl text-center">
        <h1 className="text-4xl font-bold mb-4">Lux Precompiles</h1>
        <p className="text-lg text-fd-muted-foreground mb-8">
          Native EVM precompiles providing high-performance cryptography, DEX operations, and blockchain primitives.
        </p>
        <div className="flex gap-4 justify-center flex-wrap">
          <Link
            href="/docs"
            className="px-6 py-3 bg-fd-primary text-fd-primary-foreground rounded-lg font-medium hover:opacity-90 transition-opacity"
          >
            Documentation
          </Link>
          <a
            href="https://github.com/luxfi/precompile"
            target="_blank"
            rel="noopener noreferrer"
            className="px-6 py-3 border border-fd-border rounded-lg font-medium hover:bg-fd-muted transition-colors"
          >
            GitHub
          </a>
        </div>

        <div className="mt-16 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 text-left">
          <div className="p-6 border border-fd-border rounded-lg">
            <h3 className="font-semibold mb-2">Cryptography</h3>
            <p className="text-sm text-fd-muted-foreground">
              ML-DSA, ML-KEM, SLH-DSA, FROST, Ringtail, CGGMP21 - Post-quantum and threshold signatures
            </p>
          </div>
          <div className="p-6 border border-fd-border rounded-lg">
            <h3 className="font-semibold mb-2">DEX Operations</h3>
            <p className="text-sm text-fd-muted-foreground">
              PoolManager, Hooks, Lending, Perpetuals - Uniswap v4-style native DEX
            </p>
          </div>
          <div className="p-6 border border-fd-border rounded-lg">
            <h3 className="font-semibold mb-2">FHE</h3>
            <p className="text-sm text-fd-muted-foreground">
              Fully Homomorphic Encryption for private on-chain computation
            </p>
          </div>
          <div className="p-6 border border-fd-border rounded-lg">
            <h3 className="font-semibold mb-2">Oracle</h3>
            <p className="text-sm text-fd-muted-foreground">
              Native price feeds and GraphQL interface via G-Chain
            </p>
          </div>
          <div className="p-6 border border-fd-border rounded-lg">
            <h3 className="font-semibold mb-2">AI Mining</h3>
            <p className="text-sm text-fd-muted-foreground">
              GPU attestation, NVTrust verification, and compute rewards
            </p>
          </div>
          <div className="p-6 border border-fd-border rounded-lg">
            <h3 className="font-semibold mb-2">10-100x Faster</h3>
            <p className="text-sm text-fd-muted-foreground">
              Native code execution vs equivalent Solidity implementations
            </p>
          </div>
        </div>

        <p className="mt-12 text-sm text-fd-muted-foreground">
          For pure Solidity implementations, see{' '}
          <a href="https://standard.lux.network" className="underline hover:text-fd-foreground">
            Lux Standard Contracts
          </a>
        </p>
      </div>
    </main>
  );
}
