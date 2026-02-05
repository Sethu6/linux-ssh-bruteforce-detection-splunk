Linux SSH Brute-Force Detection using Splunk

Project Overview

This project demonstrates how to detect SSH brute-force attacks on a Linux system by analyzing authentication logs and creating a time-based alert in Splunk SIEM

Tools & Technologies

Ubuntu Linux
OpenSSH
Splunk Enterprise
Splunk Universal Forwarder
SPL (Search Processing Language)

Attack Simulation

Generated multiple failed SSH login attempts using invalid usernames.
Simulated a brute-force attack pattern within a short time window.
Example command used:
ssh fakeuser@localhost

Log Source

Linux authentication logs:
/var/log/auth.log
Logs forwarded to Splunk using Universal Forwarder.

Detection Logic

The detection identifies SSH brute-force behavior by:
Extracting the source IP from failed SSH login events
Grouping events into 5-minute time windows
Alerting when failed attempts exceed a threshold

SPL Query Used
index=linux sshd "Failed password" earliest=-5m latest=now
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count as failed_attempts by src_ip, _time
| where failed_attempts > 10

Alert Configuration

Alert Type: Scheduled
Execution: Every 5 minutes (cron)
Trigger Condition: Number of results > 0
Action: Logged to Triggered Alerts

 Outcome

Successfully detected simulated SSH brute-force attacks.
Alert triggered automatically in Splunk.
Demonstrates SOC-level detection and alerting workflow.

Skills Demonstrated

Linux log analysis
SSH attack detection
Splunk SPL (rex, stats, bin, time windows)
SIEM alert creation
SOC alert triage fundamentals

Screenshots

Screenshots are included to show:
Failed SSH login events
Detection results
Triggered alert in Splunk

SOC Analyst Perspective

This detection mimics how real SOC teams identify and respond to brute-force attacks using time-based correlation and thresholding.
