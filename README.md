# Linux SSH Brute-Force Detection using Splunk
## Project Overview

This project demonstrates how to detect SSH brute-force attacks on a Linux system by analyzing authentication logs and creating a time-based alert in Splunk SIEM.

## Tools & Technologies

Ubuntu Linux

OpenSSH

Splunk Enterprise

Splunk Universal Forwarder

SPL (Search Processing Language)

## Attack Simulation

Multiple failed SSH login attempts were generated using invalid usernames to simulate a brute-force attack pattern within a short time window.

Example command used:

ssh fakeuser@localhost

## Log Source

Linux authentication logs:

/var/log/auth.log


Logs were forwarded to Splunk using the Universal Forwarder.

## Detection Logic

The detection identifies SSH brute-force behavior by:

Filtering failed SSH login events

Extracting the source IP address

Grouping events into 5-minute time windows

Alerting when failed login attempts exceed a defined threshold

This approach helps distinguish between normal user mistakes and automated attack behavior.

## SPL Query Used

index=linux sshd "Failed password" earliest=-5m latest=now

| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"

| bin _time span=5m

| stats count as failed_attempts by src_ip, _time

| where failed_attempts > 10

#### Explanation:
If an IP address generates more than 10 failed SSH login attempts within any 5-minute window, it is flagged as a potential brute-force attack.

## Alert Configuration

Alert Type: Scheduled

Execution: Every 5 minutes (cron-based)

Trigger Condition: Number of results > 0

Action: Logged to Triggered Alerts

## Outcome

Successfully detected simulated SSH brute-force attacks

Alert triggered automatically in Splunk

Demonstrates a complete SOC detection and alerting workflow

## Skills Demonstrated

Linux authentication log analysis

SSH brute-force attack detection

Splunk SPL (rex, stats, bin, time windows)

SIEM alert creation

SOC alert triage fundamentals

## Screenshots

Screenshots included in this repository show:

Failed SSH login events

Detection query results

Triggered alerts in Splunk

## SOC Analyst Perspective

This project mirrors how real SOC teams detect and respond to brute-force attacks using time-based correlation and threshold-based alerting to reduce false positives.
