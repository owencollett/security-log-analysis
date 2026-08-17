# Security Log Analysis

This project analyzes simulated authentication and security event logs to identify suspicious login behavior and high-risk activity.

## Technologies
- Python
- pandas
- Splunk SPL

## Dataset
The dataset contains more than 18,000 synthetic security events across users, hosts, IP addresses, and event types. Event types include successful logins, failed logins, file access, privilege changes, and malware alerts.

## Detection Logic
The analysis identifies repeated failed login attempts by user and source IP, successful logins following bursts of failed attempts, privilege changes, malware alerts, and external authentication activity. A suspicious authentication sequence is intentionally included in the synthetic dataset so the detection rules can be validated.

## Repository Structure
```text
data/
    auth_security_events.csv
outputs/
    brute_force_candidates.csv
    high_risk_events.csv
    suspicious_success_after_failures.csv
detect_incidents.py
splunk_queries.md
README.md
```

## Running the Project
```bash
pip install pandas
python detect_incidents.py
```

The file `splunk_queries.md` contains SPL queries for investigating failed logins, high-risk events, and external authentication activity.
