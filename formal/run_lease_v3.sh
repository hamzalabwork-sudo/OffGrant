#!/bin/bash
# Runs the lease configurations: the six that drop one rule (quick counterexamples) first, then the safe
# configuration lease_v3_ok, which explores the whole state space. If WAIT_PID is set, lease_v3_ok starts only
# after that process (e.g. another TLC runner) has exited, so that the two do not compete for disk.
cd "$(dirname "$0")"
J=${TLA2TOOLS:-tla2tools.jar}
W=${WORKERS:-16}
mkdir -p results
for c in lease_v3_eps1 lease_v3_stale lease_v3_noepoch lease_v3_receipt lease_v3_short lease_v3_nohold; do
  java -XX:+UseParallelGC -Xmx8g -jar $J -workers 4 -cleanup -deadlock -config $c.cfg LeaseV3.tla > results/$c.out 2>&1
done
if [ -n "$WAIT_PID" ]; then
  while kill -0 "$WAIT_PID" 2>/dev/null; do sleep 30; done
fi
java -XX:+UseParallelGC -Xmx24g -jar $J -workers $W -cleanup -deadlock -config lease_v3_ok.cfg LeaseV3.tla > results/lease_v3_ok.out 2>&1
echo ALLDONE > results/lease_done
