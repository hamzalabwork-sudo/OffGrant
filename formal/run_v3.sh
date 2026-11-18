#!/bin/bash
# Runs every v3 TLC configuration; one result file per configuration in results/.
cd ~/offgrant/formal
J=${TLA2TOOLS:-tla2tools.jar}
mkdir -p results
for c in lease_v3_ok lease_v3_eps1 lease_v3_stale lease_v3_noepoch lease_v3_receipt lease_v3_short; do
  java -XX:+UseParallelGC -Xmx24g -jar $J -workers 16 -deadlock -config $c.cfg LeaseV3.tla > results/$c.out 2>&1
done
for c in rights_v3_byz0 rights_v3_byz1 rights_v3_byz2 rights_v3_byz3 rights_v3_byz4; do
  java -XX:+UseParallelGC -Xmx24g -jar $J -workers 16 -deadlock -config $c.cfg RightsV3.tla > results/$c.out 2>&1
done
echo ALLDONE > results/v3_done
