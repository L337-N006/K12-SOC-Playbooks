Runbook: Context-Aware Access Proxy Pivot Detection



1\. Executive Summary \& Operational Impact



Why Deploy This Playbook?



When K-12 school districts implement Context-Aware Access (CAA) or geofencing policies to secure student and staff accounts, threat actors adapt quickly. A common attack pattern involves an adversary attempting to authenticate directly from an unauthorized country. After hitting the CAA geofence block wall, the adversary immediately routes their connection through a domestic US proxy server or residential VPN endpoint to bypass the geographic restriction.



Because this entire shift—from a blocked overseas access attempt to a successful US-authenticated login—takes place rapidly (typically within a 2-to-5 minute window), manually correlating separate log streams across millions of student events is impossible.



What It Solves



This playbook addresses a critical gap: Google Admin SDK Reports API log propagation latency. Workspace directory events are processed asynchronously; login records and context-aware tracking matrices routinely take anywhere from 15 minutes to 4 hours to sync to API endpoints.



This engine eliminates detection blindness by maintaining a continuous, deduplicated correlation loop. It scans an expanded lookback window to catch out-of-order log deliveries, automatically pairing geographic policy denials with subsequent login successes for the same identity while suppressing duplicate card dispatches.



2\. Technical Architecture \& Directory Mapping



Folder Structure



To integrate this tool suite into your local copy of the K12-SOC-Playbooks repository, organize the files as follows:



K12-SOC-Playbooks/

└── playbooks/

&#x20;   └── gws-caa-proxy-pivot/

&#x20;       ├── README.md             <-- This Documentation

&#x20;       ├── caas\_proxy\_alerter.py <-- Production Detection Script

&#x20;       └── mock\_gam.py           <-- Simulation Testing Script





3\. Production Deployment Playbook



Step 1: Clone and Navigate to your Local Repository



Open your terminal (PowerShell on Windows, or WSL Bash) and navigate to your localized playbook workspace:



cd C:\\Users\\Giovanni\\K12-SOC-Playbooks





Step 2: Establish the Playbook Directory Block



mkdir -p playbooks/gws-caa-proxy-pivot





Step 3: Configure the Scripts



Place the universal engine script (caas\_proxy\_alerter.py) and the mock testing harness (mock\_gam.py) into the newly created folder:

playbooks/gws-caa-proxy-pivot/



4\. Universal Execution Settings (Windows, Linux \& WSL)



Our codebase automatically detects the underlying operating system and scales natively.



Execution on WSL / Linux



Ensure the script is marked as executable and has local environment variables declared:



chmod +x playbooks/gws-caa-proxy-pivot/caas\_proxy\_alerter.py



\# Execute directly

python3 playbooks/gws-caa-proxy-pivot/caas\_proxy\_alerter.py





Scheduling with Linux Cron (WSL)



Open your crontab config (crontab -e) and add this job to execute every 5 minutes:



\*/5 \* \* \* \* export GAM\_CONFIG\_DIR="/home/\[YOUR\_LINUX\_USER]/.gam" \&\& /usr/bin/python3 /home/\[YOUR\_LINUX\_USER]/K12-SOC-Playbooks/playbooks/gws-caa-proxy-pivot/caas\_proxy\_alerter.py >> /home/\[YOUR\_LINUX\_USER]/soc/logs/caas\_proxy\_hunter.log 2>\&1





Scheduling with Windows Task Scheduler



If running natively on a Windows Admin host, create a basic task scheduled to repeat every 5 minutes executing your script wrapper:



$Action = New-ScheduledTaskAction -Execute "python.exe" -Argument "C:\\Users\\Giovanni\\K12-SOC-Playbooks\\playbooks\\gws-caa-proxy-pivot\\caas\_proxy\_alerter.py"

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)

Register-ScheduledTask -TaskName "GWS-ProxyPivot-Detection" -Action $Action -Trigger $Trigger -User "NT AUTHORITY\\SYSTEM" -RunLevel Highest





5\. Defensive Playbook Actions (Triage Protocol)



When an alert triggers in the team's dashboard space indicating a successful proxy pivot sequence has bypassed the geofence perimeter, execute this automated tactical isolation script straight through the CLI to drop the threat actor's active footholds:



\# Force sign-out of all concurrent active web/app sessions

gam user \[COMPROMISED\_USER\_EMAIL] signout



\# Invalidate and revoke all dynamic third-party OAuth access token profiles

gam user \[COMPROMISED\_USER\_EMAIL] deauthorize



\# Apply directory-level suspension to secure the tenant environment immediately

gam user \[COMPROMISED\_USER\_EMAIL] update suspect on suspend on



