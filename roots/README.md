# Signed daily hash-chain roots (x402 Trust Index)

Each `YYYY-MM-DD.root.json` is the Ed25519-signed Merkle root of that day's observed x402
registry records (resources, snapshots, events, probes, trust). Each root includes
`previous_root` = the prior day's `root_hash`, forming a tamper-evident hash chain.

These files contain only hashes and minimal metadata — no original content or secrets.
Publishing them here time-stamps the record independently: the observation history cannot
be back-dated.

Verify:
```
python -m kkj.attest verify-root YYYY-MM-DD
python -m kkj.attest prove-resource RESOURCE_ID YYYY-MM-DD
```
Or independently: `root_hash = sha256(canonical({date,previous_root,records_count,merkle_root,created_at}))`,
then `Ed25519.verify(public_key, signature, utf8(root_hash))`. Merkle: `leaf=sha256(canonical(record))`,
`node=sha256(left||right)`, duplicate last if odd.
