#!/bin/bash
tcpdump -i en0 -w trace.pcap & sleep 3          #capture tous les trames passer sur en0 dans 3 secondes
exit