\# runZero Topology Mapper (SNMP/LLDP)

\*\*Language:\*\* Bash / CLI

\*\*Dependencies:\*\* `jq`

\*\*Purpose:\*\* Extracts physical switch port mapping (Asset IP, Hostname, Switch IP, Switch Port) from a raw runZero JSONL export. Eliminates manual cable tracing.



\## Prerequisites

\* A runZero Services/Software JSONL export containing devices polled via SNMP.

\* `jq` installed on your system.



\## The Execution

Run this in your terminal in the same directory as your runZero `\*.jsonl` export files:



```bash

jq -r 'select(.attributes."\_links.ports.connected" != null) | \[.addresses\[0], .names\[0], .attributes."\_links.ports.connected"] | @tsv' \*.jsonl > switch\_mapping\_output.tsv

