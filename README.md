# OffGrant: an accountable offline blockchain for industrial IoT

Industrial sites lose their uplinks for seconds to days. OffGrant lets a cut-off site keep acting, on its own
PureChain (Clique) ledger, on rights issued in advance by a global ledger G: versioned resource shares, leases on
exclusive objects (bounded or open holds) and credential leases. A grant takes effect only when the site gateway
executes it with a fresh reading of the site's TPM 2.0 clock, inside a lease counted from the send of its renewal
request and bound to the clock's power epoch, which meets the lease bound D(1+rho)/(1-rho). Checkpoints carry
clock-attested closes and committed running totals: G renews only sites whose checkpoints are anchored, and every
recorded violation is proven at constant cost against faulty validators only.

## Layout

| Path | Contents |
|---|---|
| `contracts/` | `RightsRegistry` (G), `SiteRights` (site ledger), `OffLib`; Foundry tests (`forge test`) |
| `formal/` | TLA+ models: `LeaseV3.tla` (lease bound with epochs, power loss, execution after finality, G timestamp error) and `RightsV3.tla` (site-ledger safety and accountability); configurations and TLC outputs in `formal/results/` |
| `prototype/` | `offsim.py` (30-day discrete-event simulator, baselines and ablations), `analyze.py`, `figs.py` |
| `experiments/offgrant/` | End-to-end harness on local PureChain networks (`e2e.py`, `e2e_analyze.py`) and the public-testnet run (`pubtest.py`) |
| `experiments/results/` | Result files of every run |
| `testbed/purechain/` | Docker image of the official PureChain v1.0.1 binary and network generator (`mknet.py`) |

## Reproducing

```sh
# contracts (solc 0.8.30 in contracts/.solc)
cd contracts && forge test
# model checking (Java 21, tla2tools.jar)
java -jar tla2tools.jar -workers auto -config formal/lease_v3_ok.cfg formal/LeaseV3.tla
# simulation grid (720 independent runs) and summary
python prototype/offsim.py --out experiments/results/offsim_v4.jsonl && python prototype/analyze.py experiments/results/offsim_v4.jsonl
# end-to-end run on local PureChain networks (testbed/purechain/mknet.py offgrant, then docker compose up)
python experiments/offgrant/e2e.py --cut 150 --tag v4 && python experiments/offgrant/e2e_analyze.py v4
```
