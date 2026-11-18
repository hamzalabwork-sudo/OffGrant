#!/bin/bash
# Reruns selected TLC configurations, each with its own state folder (removed after the run), so that runs can
# go on in parallel with another runner. Usage: ./run_more.sh WORKERS cfg1 [cfg2 ...]
cd "$(dirname "$0")"
J=${TLA2TOOLS:-tla2tools.jar}
W=$1
shift
mkdir -p results scratch
for c in "$@"; do
  case $c in rights*) M=RightsV3.tla ;; *) M=LeaseV3.tla ;; esac
  java -XX:+UseParallelGC -Xmx16g -jar $J -workers $W -metadir "scratch/$c" -deadlock -config $c.cfg $M > results/$c.out 2>&1
  rm -rf "scratch/$c"
done
