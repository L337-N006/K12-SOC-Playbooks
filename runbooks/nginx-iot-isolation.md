\# Operational Runbook: Nginx Buffer Overflow Remediation (IoT Fleet)

\*\*Target Hardware:\*\* UPS Management Cards, Smart Printers

\*\*Tooling Used:\*\* runZero, SNMP/LLDP Topology Mapping, Switch CLI



\## 1. The Operational Issue

A critical vulnerability affects the Nginx web server running on embedded IoT devices (UPS cards, printers). 

\* \*\*The Flaw:\*\* Heap-based buffer overflow via malformed HTTP requests.

\* \*\*The Impact:\*\* Service crashes and potential arbitrary remote code execution (RCE).

\* \*\*The Challenge:\*\* Endpoint agents (EDR) cannot be installed on IoT hardware, and vendor firmware patches are often delayed. Immediate network-level containment is required.



\## 2. Topology Mapping (No Cable Tracing Required)

Instead of manual MAC address hunting, utilize runZero's SNMP/LLDP polling to find the exact switch ports.

1\. Query the fleet for the vulnerable Nginx versions.

2\. Export the telemetry and parse the `\_links.ports.connected` attribute.

3\. Generate a direct map of \*\*Asset IP -> Switch IP -> Physical Switch Port\*\*.



\## 3. Immediate Containment Actions

Execute network-level isolation based on the device type to minimize operational disruption.



\*\*A. UPS Management Cards (Switch Port Shutdown)\*\*

\* \*\*Action:\*\* Using the switch mapping, log into the core routing infrastructure and administratively disable (`shutdown` / `Admin Down`) the specific switch ports supplying network access to the vulnerable cards.

\* \*\*Result:\*\* The UPS units continue to provide backup power, but their management interfaces are completely air-gapped from the network.



\*\*B. Smart Printers (Network Segmentation Validation)\*\*

\* \*\*Action:\*\* Disabling switch ports for printers disrupts end-user operations. Instead, verify the network placement of all vulnerable printers.

\* \*\*Result:\*\* Ensure printers are connected exclusively to a restricted Guest/IoT Wi-Fi SSID. Layer 3 ACLs must prevent these devices from routing traffic to internal, trusted corporate subnets.



\## 4. Next Steps (Day 2 Operations)

\* \*\*Task 1: Firmware Upgrades.\*\* Flash the affected devices once vendors release patched firmware.

\* \*\*Task 2: Port Restoration.\*\* Only after a device is successfully flashed, re-enable the switch port (`no shutdown`) to restore remote management visibility.

\* \*\*Task 3: Long-Term Hardening.\*\* Move all infrastructure management cards to a dedicated, non-routable \*\*Management VLAN\*\* with strict jump-box access, ending reliance on reactive port shutdowns.(If you actually need them to notify. We opted to just keep them air-gapped.)

