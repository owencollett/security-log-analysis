# Security Log Analysis

I built this project to practice working with authentication and security-event data using Python and basic Splunk SPL. The dataset contains more than 18,000 synthetic events across users, hosts, IP addresses, and several event types.

## What I looked for

The analysis focuses on a few common security-monitoring patterns:

- repeated failed login attempts from the same user and source IP
- successful logins that occur after a burst of failed attempts
- privilege-change and malware-alert events
- authentication activity from unexpected locations or contexts

The Python script uses simple rule-based logic rather than a machine-learning model. The goal is to identify events that deserve investigation, not to label activity as malicious automatically.

## Example result

One synthetic sequence produced **28 failed logins** for `user17` from `203.0.113.77`. The same sequence also included successful logins after 25–28 failed attempts within the previous 30 minutes, which the script flagged as high-severity events for review.

Because the dataset is synthetic, these results are examples of how the detection logic behaves rather than evidence of a real incident.

## Tools

- Python
- pandas
- Splunk SPL

## Project files

- `detect_incidents.py` — loads the event data and applies the detection rules
- `SPLUNK_QUERIES.md` — SPL queries for failed logins, high-risk events, login trends, and external authentication activity
- `data/auth_security_events.csv` — synthetic event dataset
- `outputs/brute_force_candidates.csv` — user/IP combinations with repeated failures
- `outputs/suspicious_success_after_failures.csv` — successful logins following repeated failures
- `outputs/high_risk_events.csv` — privilege-change and malware-alert events

## Run the analysis

```bash
pip install pandas
python detect_incidents.py
```

The SPL examples in `SPLUNK_QUERIES.md` mirror several of the same investigation questions using Splunk search syntax.
