#!/bin/bash
# Repeated end-to-end runs (contracts v6): three with a clean 150-s cut, three with a flapping, lossy uplink.
cd "$(dirname "$0")"
for r in 1 2 3; do
  python -u e2e.py --cut 150 --tag v6_r$r > ../results/e2e_v6_r$r.log 2>&1
  python -u e2e.py --cut 150 --flap --seed $((6 + r)) --tag v6flap_r$r > ../results/e2e_v6flap_r$r.log 2>&1
done
python e2e_analyze.py --agg v6 v6_r1 v6_r2 v6_r3 > ../results/e2e_v6_agg.log 2>&1
python e2e_analyze.py --agg v6flap v6flap_r1 v6flap_r2 v6flap_r3 > ../results/e2e_v6flap_agg.log 2>&1
