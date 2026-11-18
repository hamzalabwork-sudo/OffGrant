# Experiments on PureChain

This guide explains how to rebuild the PureChain testbed and reproduce every experiment. It also explains what
each output means.

- [Requirements](#requirements)
- [Testbed](#testbed)
- [1. The problem: one chain across sites](#1-the-problem-one-chain-across-sites)
- [2. OffGrant end to end](#2-offgrant-end-to-end)
- [3. Public PureChain testnet](#3-public-purechain-testnet)
- [4. Figures](#4-figures)
- [Result files](#result-files)

## Requirements

| Tool | Used for |
|---|---|
| Docker (with Compose) | PureChain nodes, uplink proxies, Foundry |
| Python 3.10+ and `pip install -r requirements.txt` | experiment drivers, simulator, analysis |
| Linux amd64 or arm64 host, or Docker Desktop | running the official PureChain binaries |

The contracts must be compiled once, which produces `contracts/out/` (read by the drivers):

```sh
cd contracts
docker run --rm -v "$PWD:/work" -w /work --entrypoint forge ghcr.io/foundry-rs/foundry:v1.8.4 build
```

See the [README quick start](../README.md#quick-start) for installing `forge-std` and choosing the compiler.

## Testbed

PureChain is a fork of geth 1.13.15 with Clique proof-of-authority, the Cancun EVM and zero gas prices. The
testbed runs the **official v1.0.1 release binary** in Docker.

**1. Get the binary and check it**

Download it from the PureChain releases
(<https://github.com/gieworld/purechain_testnet/releases/tag/v1.0.1>) and check it against the release's
`SHA256SUMS.txt`:

```sh
mkdir -p testbed/purechain/bin && cd testbed/purechain/bin
# download purechain-geth-v1.0.1-linux-amd64 and SHA256SUMS.txt from the release page, then:
sha256sum -c SHA256SUMS.txt --ignore-missing
cd ../../..
```

**2. Build the node image**

The image adds `tc` (for netem fault injection) and `socat` (for the uplink proxies):

```sh
docker build -t offgrant/purechain:1.0.1 testbed/purechain
```

**3. Generate and start a network**

`mknet.py` writes `testbed/purechain/net_<layout>/`, which holds throwaway keys, genesis files, static peers,
`docker-compose.yml` and `nodes.json` (node names, addresses and RPC ports). This folder is git-ignored and its
keys never leave it.

| Layout | Chains | RPC ports on 127.0.0.1 |
|---|---|---|
| `span` | one chain, 12 signers spread over three sites (4 each) | 8600–8603, 8610–8613, 8620–8623 |
| `offgrant` | global chain `G` (4 signers), one chain per site (4 signers each), one uplink proxy per site | `G` 8700–8703; site 1 8710–8713; site 2 8720–8723; uplink proxies 8791, 8792 |

```sh
python testbed/purechain/mknet.py offgrant          # or: span
docker compose -f testbed/purechain/net_offgrant/docker-compose.yml up -d
```

In the `offgrant` layout, a site's relayer reaches `G` only through its uplink proxy (`up1`, `up2`). Cutting a
site's uplink means adding a netem rule that drops all of the proxy's traffic:
`docker exec up1 tc qdisc add dev eth0 root netem loss 100%`. The site's own chain keeps running.

**Check that every chain is producing blocks** (one block per second) before starting an experiment. A Clique
signer that was stopped can need a restart of its whole chain before it seals again.

## 1. The problem: one chain across sites

`experiments/span_demo.py` uses the `span` layout. It cuts site C (4 of 12 signers) off from the other two sites
for `--cut` seconds while site C keeps submitting operations. It records every site's chain head once per second,
and at the end checks which of C's operations reached the canonical chain, and when.

```sh
python experiments/span_demo.py --cut 120 --after 60
```

Output: `experiments/results/span_demo.json`. In our run, the cut-off site's chain stayed at one block while the
others advanced 101, and its operations waited up to 122.9 s.

## 2. OffGrant end to end

`experiments/offgrant/e2e.py` runs the whole protocol on the `offgrant` layout, in real time.

**Setup**

- **Contracts.** It deploys `RightsRegistry` on `G` and `SiteRights` on each site, and creates objects for each
  site:

  | Object | Kind |
  |---|---|
  | P11, P12, P21, P22 | permits (exclusive, bounded holds) |
  | L11 | lockout point (exclusive, open hold) |
  | C11, C21 | credentials |

- **Clocks.** Site clocks are TPM stand-ins: site 1 runs at the 15% slow limit, site 2 at +5%.
- **Time compression.** `D = 60 s` and `W = 86 s`, so a run takes minutes.

**Threads per site**

- **Relayer:** anchors the newest checkpoint, sends renewal requests every 4 s, applies stops and sends
  fast-path acknowledgements.
- **Checkpointer:** every 6 s, each validator builds a checkpoint from its own node; the checkpoint is signed
  when all views agree.
- **Gateway:** executes final grants after a fresh clock check. A grant that no longer fits lapses.
- **Operator:** a random workload of permits, credentials, locks and releases, consumption and records.

**Scenario** (seconds after a 25 s warm-up)

| Time | Event |
|---|---|
| 20 | site 1's uplink is cut for `--cut` seconds (default 150) |
| 35 | `G` stops P11 and L11 in favour of site 2; P11 moves by the slow path at `W`, and L11's slow path is refused |
| 45 | `G` revokes credential C11 of site 1 |
| 20 + cut | site 1 reconnects: one anchor catches up; stops are applied; L11 moves once its lock is released |
| + 30 | `G` stops P21 (site 2, connected): it moves by the fast path once every hold has ended |
| + 60 | site 2 loses power (new clock epoch) |

**Attacks**

After the scenario, a faulty quorum of site 1 (validators 0–2) seals ten kinds of violation, each against a fresh
registry, and the driver submits the fraud proofs. It also anchors a checkpoint with a forged close. Finally, it
tries every applicable proof against every honest checkpoint of the run.

**Running it**

```sh
cd experiments/offgrant
python e2e.py --cut 150 --tag v4            # clean cut
python e2e.py --cut 150 --tag v4flap --flap # lossy, flapping uplink instead of a clean cut
python e2e_analyze.py v4
```

`--flap` makes site 1's uplink alternate between cut and degraded (800 ± 400 ms delay, 20% loss) for random
3–15 s periods.

**Reading the summary** (`experiments/results/e2e_<tag>_summary.json`)

| Key | Meaning |
|---|---|
| `effect_safety` | for each object that moved: when it moved, when the old holder's last effect ended, the margin, and how many effects ended after the move (must be 0) |
| `lapses` | grants refused at execution (window or lease passed, or new epoch) |
| `grant_to_effect_s` | time from a grant to its execution (finality) |
| `slow_path_P11` | stop-to-move time, the lease end, the move time and the last effect |
| `open_hold_L11` | the refused slow path, then the acknowledged move after the lock's release |
| `revocation_C11` | credential acceptances after the revocation, against the bound `W` |
| `fast_path_P21` | stop-to-move time when the holder is connected |
| `clock_reset` | grants that lapsed in the old epoch, and when the site worked again |
| `catch_up` | how soon after reconnection one anchor covered the outage, and how many checkpoints it covered |
| `anchors` | all anchors, including any that failed |
| `site1_during_cut_*` | what site 1 recorded and executed while cut off |
| `gas_median`, `stop_gas` | gas of each transaction type |
| `attacks` | for each attack: transaction status, gas and number of validators slashed; `forged_close`; `no_framing` with the contract's verdict on every proof attempt against honest operations |

## 3. Public PureChain testnet

`experiments/offgrant/pubtest.py` deploys `RightsRegistry` on the public PureChain testnet (chain id
900520900520). It then measures the gas and confirmation latency of renewals, anchors, stops, fast-path
reassignment and fraud proofs. It needs two funded keys in a git-ignored `.env` file (`ADMIN_KEY`, `GATEWAY_KEY`),
read from `testbed/purechain/.env` or the path in `OFFGRANT_KEYS_ENV`. Keys are never printed. Site validators
and clocks use throwaway local keys.

```sh
OFFGRANT_KEYS_ENV=/path/to/.env python experiments/offgrant/pubtest.py v2
```

Output: `experiments/results/pubtest_<tag>.json`, containing addresses, gas and latencies (no keys).

## 4. Figures

`prototype/figs.py` draws the paper's figures from the simulation and end-to-end results into `paper/figures/`
(created if missing):

```sh
python prototype/figs.py
```

## Result files

Every version of every experiment is kept, so changes between versions can be compared. The current versions are
listed first.

| File | Contents |
|---|---|
| `e2e_v4.json`, `e2e_v4_summary.json`, `e2e_v4.log` | end-to-end run (clean cut) with the current contracts |
| `e2e_v4flap.*` | the same scenario with a flapping, lossy uplink |
| `forge_test_v3.log` | the contract test run |
| `offsim_v4.jsonl`, `offsim_v4_summary.txt` | current simulation grid and summary |
| `pubtest_v2.json` | public testnet measurements |
| `span_demo.json` | the single-chain problem demonstration |
| `e2e_v1`–`e2e_v3`, `offsim_v1`–`offsim_v3`, `pubtest_v1` | earlier versions |
