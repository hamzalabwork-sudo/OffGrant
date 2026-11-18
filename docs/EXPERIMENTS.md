# Experiments on PureChain

This guide explains how to rebuild the PureChain testbed and reproduce every experiment. It also explains what
each output means.

- [Requirements](#requirements)
- [Testbed](#testbed)
- [1. The problem: one chain across sites](#1-the-problem-one-chain-across-sites)
- [2. OffGrant end to end](#2-offgrant-end-to-end)
- [3. Public PureChain testnet](#3-public-purechain-testnet)
- [4. Reconnection storm](#4-reconnection-storm)
- [5. Figures](#5-figures)
- [Result files](#result-files)

## Requirements

| Tool | Used for |
|---|---|
| Docker (with Compose) | PureChain nodes, uplink proxies, Foundry |
| Python 3.10+ and `pip install -r requirements.txt` | experiment drivers, simulator, analysis |
| Linux amd64 or arm64 host, or Docker Desktop | running the official PureChain binaries |

The contracts must be compiled once, which produces `contracts/out/` (read by the drivers). They compile through
the IR pipeline, which takes about a minute:

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

`experiments/offgrant/e2e.py` runs the whole protocol (contract version 6) on the `offgrant` layout, in real
time.

**Setup**

- **Contracts.** It deploys `RightsRegistry` on `G` and `SiteRights` on each site. Each site gets a share of 40
  spare parts (of a cap of 100). It creates these objects, each with its class fixed at creation:

  | Object | Kind |
  |---|---|
  | P11, P12, P21, P22 | permits (exclusive, bounded holds) |
  | L11 | lockout point (exclusive, open holds) |
  | C11, C21 | credentials |

  The first digit after the letter is the site that holds the object at the start. Every site learns every lease,
  because an object may move to it later.
- **Clocks.** Site clocks are TPM stand-ins with epochs and strictly increasing attested readings. Site 1 runs at
  the 15% slow limit, site 2 at +5%.
- **Time compression.** `D = 60 s` and `W = 86 s`, so a run takes minutes.

**Threads per site**

- **Relayer:** in rounds 4 s apart, anchors the newest checkpoint and sends one clock-attested renewal request
  for all the objects the site may renew (a batch renewal). Once the renewal is final on `G`, it applies the
  certificate on the site ledger. It also applies stops and share certificates, confirms a lowered share from a
  sealed checkpoint, and runs the fast path.
- **Checkpointer:** every 6 s, each validator reads the new operations from its own node, three blocks behind
  the head. Every validator whose view agrees signs the checkpoint; it needs at least 3 of 4. The checkpoint
  commits the operations, the state and the history of all earlier checkpoints, and carries a clock-attested
  close.
- **Gateway:** the only component that attests. It verifies `G`'s renewal, stop and share certificates itself,
  attests a grant only in the current epoch and inside the allowance, and a release only by the crew that applied
  the lock. It executes grants that are in a sealed checkpoint, after a fresh clock check; a grant that no longer
  fits lapses. It attests an `ACK` only when no hold of the object can still be in effect, including holds of an
  earlier epoch, which it waits out scaled by `(1+ρ)/(1−ρ)` after a power loss.
- **Operator:** a random workload of permits, credentials, locks and releases, consumption and records. Every
  operation that uses a right is attested by the site clock. A lock stays on for 20 s, and its release names the
  hold it ends and the crew; another crew's attempt to release it is made once per run and must be refused.

**Scenario** (seconds after a 25 s warm-up)

| Time | Event |
|---|---|
| 10 | `G` lowers site 2's share of parts from 40 to 30. Site 2 applies it as a `SHARE` operation; `G` frees the capacity once a sealed checkpoint shows the new version (`confirmShare`) |
| 20 | site 1's uplink is cut for `--cut` seconds (default 150) |
| 35 | `G` stops P11 and L11 in favour of site 2; P11 moves by the slow path at `W`, and L11's slow path is refused |
| 45 | `G` revokes credential C11 of site 1 |
| 20 + cut | site 1 reconnects: one anchor catches up; stops are applied; L11 moves by acknowledgement once its lock is released |
| + 30 | `G` stops P21 (site 2, connected): it moves by the fast path once every hold has ended |
| + 52 | a crew at site 2 takes permit P22, so a hold is running when the power fails |
| + 60 | site 2 loses power (new clock epoch); its actuators drop the P22 hold |
| + 62 | `G` stops P22: it moves by acknowledgement once the gateway has waited out the old epoch's holds |
| + 130 | end of the scenario |

**Attacks**

After the scenario, a faulty quorum of site 1 seals 22 kinds of violation. Each is submitted as a fraud proof
against a fresh registry, so that the slashing counts are independent.

| Attack | Proof |
|---|---|
| `overspend` | `proveOverspend` |
| `understate` (a running total that restarts lower) | `proveInconsistent` |
| `state_regress` (a committed total that goes back) | `proveRegress` |
| `restart_below_anchor` (ancestor 299 heights back) | `proveOpRegress` |
| `stale_share_version` (consumption under the old version after `confirmShare`) | `proveOpRegress` |
| `state_mismatch`, `state_above_share`, `oversized_state` | `proveStateMismatch` |
| `overuse`, `hold_past_allowance`, `use_after_reset` | `proveOveruse` |
| `replayed_attestation` | `proveInconsistent` |
| `forged_release` (a release the clock never attested) | `proveBadOp` |
| `ack_with_lock_on` (lock and release counts differ) | `proveBadOp` |
| `ack_hides_lock`, `ack_hides_earlier_lock` | `proveInconsistent`, `proveOpRegress` |
| `lock_counter_regress` (a lock dropped from the committed state) | `proveRegress` |
| `use_after_ack`, `release_after_ack`, `release_after_ack_new_epoch` | `proveUseAfterAck` |
| `fork`, `fork_across_heights` (ancestor 499 heights back) | `proveFork` |

Validators 0–2 seal each violation. For the acknowledgement and fork attacks, the second quorum is validators
1–3, so only the 2 validators in both quorums are provably faulty. The driver also checks five actions that must
be rejected outright: a checkpoint with a forged close, a grant's attestation offered as an acknowledgement, the
override before `W`, a renewal of a retired site, and a proof against a retired site's honest history.
Finally, it tries every applicable proof against every honest sealed operation, against pairs of honest
checkpoints, and against every acknowledgement of the run. Each attempt must revert with `NotAViolation`.

**Running it**

```sh
cd experiments/offgrant
python e2e.py --cut 150 --tag v6_r1                    # clean cut
python e2e.py --cut 150 --flap --seed 7 --tag v6flap_r1  # lossy, flapping uplink instead of a clean cut
python e2e_analyze.py v6_r1
bash run_e2e_v6.sh   # all six runs of the paper (about 18 minutes each), then the aggregates
```

`run_e2e_v6.sh` writes `e2e_v6_agg.json` and `e2e_v6flap_agg.json`, with the minimum, median and maximum of each
measure over the three runs per uplink fault.

`--flap` makes site 1's uplink alternate between cut (3–15 s) and slow and lossy (800 ± 400 ms delay, 20% loss,
10–30 s).

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
| `fast_path_P22_after_reset` | the same after site 2's power loss, with the holds carried from the old epoch and how long the gateway waited |
| `locks`, `gateway_refusals` | lock requests, those recorded, those the gateway refused and why, and the other crew's release attempts |
| `ack_ops` | `ACK` operations recorded on the site ledgers, their gas, and any refused |
| `share_lowering` | when the lower share was set on `G`, applied on the site ledger and confirmed on `G` |
| `renewal_interval_per_object_s` | time between two renewals of one object (batch renewals) |
| `clock_reset` | grants that lapsed in the old epoch, and when the site worked again |
| `catch_up` | how soon after reconnection one anchor covered the outage, and how many checkpoints it covered |
| `anchors`, `checkpoints` | all anchors, including any that failed; all checkpoints, and whether every validator agreed |
| `site1_during_cut_*` | what site 1 recorded and executed while cut off |
| `op_latency_s`, `renewal_latency_s` | latency of site operations and of renewals (request sent to certificate applied) |
| `gas_median`, `stop_gas` | gas of each transaction type |
| `attacks` | for each attack: transaction status, gas and number of validators slashed; `forged_close` and `grant_attestation_as_ack`; `no_framing` with the contract's verdict on every proof attempt against honest data |

**Our runs** (three clean, three flapping; minimum / median / maximum, or totals):

| Measure | Clean cut | Flapping uplink |
|---|---|---|
| Effects ending after their object moved | 0 | 0 |
| Margin to the move: P11 (slow path) | 42 / 47 / 47 s | 8.6 / 9.0 / 29 s |
| L11 / P21 / P22 (by acknowledgement), median | 112 / 57 / 52 s | 92 / 49 / 54 s |
| Catch-up anchor after reconnection | 2.3 / 3.2 / 3.3 s (23-25 checkpoints) | 2.5 / 9.6 / 12 s (13-24) |
| Grant to effect, median | 9.7 s | 9.5 s |
| Anchors logged / on chain | 182 / 182 | 180 / 180 |
| Attacks slashed / rejections | 22 / 5 in every run | 22 / 5 in every run |
| Proof attempts on honest data | 4,001, all `NotAViolation` | 4,075, all `NotAViolation` |

Each object was renewed every 16 s (median) with batch renewals. All four validators agreed on every checkpoint.
In an earlier batch of three flapping runs (`results/superseded_v6_prefix/`, whose harness differed only in a fix
to the scripted P22 grant), a renewal sent just before a cut arrived 8.5 s and 8.8 s late; counted from the send,
the allowance ended 8.4 s and 8.7 s before `G` moved P11, while counted from the receipt it would have run past the
move.

## 3. Public PureChain testnet

`experiments/offgrant/pubtest.py` deploys `RightsRegistry` (contract version 6) on the public PureChain testnet
(chain id 900520900520) and runs the global-ledger side of the protocol there, about 45 transactions:

1. register two sites and issue a share and a lease;
2. send 24 clock-attested batch renewals, anchoring the newest checkpoint of site 1's (locally kept) ledger after
   every 8, since `G` renews only sites whose anchored coverage is recent;
3. try every applicable fraud proof against every honest anchored operation and checkpoint pair (read-only
   calls; all must revert with `NotAViolation`);
4. stop the object and move it by the fast path: an attested `ACK` operation, acknowledged by three site
   validators;
5. submit two real fraud proofs by faulty quorums: an overspend (3 validators slashed) and a grant after the
   acknowledgement (the 2 validators in both quorums slashed).

It needs two funded keys in a git-ignored `.env` file (`RPC`, `ADMIN_KEY`, `GATEWAY_KEY`), read from
`testbed/purechain/.env` or the path in `OFFGRANT_KEYS_ENV`. Keys are never printed. Site validators and clocks use
throwaway local keys. To try it first on the local network, point `OFFGRANT_KEYS_ENV` to a file with
`RPC=http://127.0.0.1:8700` and two keys from `testbed/purechain/net_offgrant/nodes.json`.

```sh
OFFGRANT_KEYS_ENV=/path/to/.env python experiments/offgrant/pubtest.py v6
```

Output: `experiments/results/pubtest_<tag>.json`, containing addresses, gas and latencies (no keys). In our run
(`pubtest_v6.json`, registry `0xeCD9df26d3D9b59f90E5c89C2DE7C085DF210c33`):

| Measurement | Result |
|---|---|
| Batch renewal of one object | confirmed in 1.95 s median (at most 2.5 s over 24), 73,696 gas |
| Batch renewal of 2 / 4 / 8 objects (first renewal of each) | 126,631 / 215,552 / 393,233 gas |
| Anchor of 24 operations | 147,869 gas |
| `stop`, fast-path move (`reassignAcked`) | 55,693 and 173,142 gas |
| Proof attempts against honest data | 313, all reverted with `NotAViolation` |
| Real fraud proofs | `Overspend` slashed 3 validators (152,137 gas), `UseAfterAck` 2 (138,288 gas) |

## 4. Reconnection storm

`experiments/offgrant/storm.py` measures what `G` absorbs when many sites reconnect at once after a regional
outage. For each number of sites, it registers that many sites on the local `G`, each with 3 objects, lets each
seal 600 checkpoints during a simulated one-hour outage (kept locally, as a site ledger would), and then reconnects
them all at once. Each site's relayer, with its own key, sends one anchor of the newest checkpoint and then one batch
renewal. It records, per site, the time until the renewal is final, and per block, the gas used.

```sh
cd experiments/offgrant
python storm.py --sites 10,25,50,100 --tag v6
```

Output: `experiments/results/storm_<tag>.json`. In our run (`storm_v6.json`):

| Sites | Every site renewed within (median) | Blocks | Most gas in one block |
|---|---|---|---|
| 10 | 4.3 s (4.3 s) | 3 | 2.0M |
| 25 | 4.7 s (4.6 s) | 3 | 4.9M |
| 50 | 6.4 s (5.3 s) | 5 | 4.7M |
| 100 | 9.7 s (8.4 s) | 8 | 8.9M |

The block gas limit is 30M. Each anchor cost 148k gas and each first batch renewal of 3 objects 197k gas, whatever
the outage length, and no transaction failed.

## 5. Figures

`prototype/figs.py` draws the paper's figures into `paper_iotj/figures/` (created if missing), as PDF and PNG:

- `tradeoff`: from `offsim_v6.jsonl`, (a) offline permit availability against `D` and (b) the longest authority
  of an old holder after a reassignment decision, relative to `D`, with every clock at the slow limit;
- `timeline`: from `e2e_v6_r1.json`, the holds in effect at the gateways for P11, L11, C11, P21 and P22, with the
  cut, stops, moves, the power loss and lapsed grants;
- `storm`: from `storm_v6.json` and `pubtest_v6.json`, (a) the time until each site holds a renewal again after a
  reconnection storm and (b) the gas of a batch renewal against its number of objects.

```sh
python prototype/figs.py
```

## Result files

Every version of every experiment is kept, so changes between versions can be compared. The current versions
(contract version 6) are listed first.

| File | Contents |
|---|---|
| `e2e_v6_r{1,2,3}.*`, `e2e_v6flap_r{1,2,3}.*` | the six end-to-end runs (events, summary, log) |
| `e2e_v6_agg.*`, `e2e_v6flap_agg.*` | minimum, median and maximum over the three runs per uplink fault |
| `superseded_v6_prefix/` | the first batch of six runs, before the fix to the scripted P22 grant (kept for the send-versus-receipt evidence) |
| `e2e_v6smoke.*` | a short smoke run of the v6 harness |
| `storm_v6.json`, `storm_v6.log` | the reconnection storm |
| `forge_test_v6.log` | the contract test run (61 tests) with contract sizes |
| `offsim_v6.jsonl`, `offsim_v6_summary.txt`, `offsim_v6.log` | current simulation grid, summary and run log |
| `pubtest_v6.json`, `pubtest_v6.log` | public testnet measurements with the current contracts |
| `span_demo.json` | the single-chain problem demonstration |
| `e2e_v1`–`e2e_v5`, `e2e_v4flap`, `e2e_v5flap`, `offsim_v1`–`offsim_v5`, `pubtest_v1`, `pubtest_v2`, `pubtest_v4`, `pubtest_v5`, `forge_test_v3.log`, `forge_test_v5.log` | earlier versions |
