# Splunk SPL Queries

After importing `data/auth_security_events.csv` into a local Splunk instance:

## Failed logins by source
```spl
index=* event_type="login_failed"
| stats count by source_ip user
| where count >= 10
| sort - count
```

## High-risk event timeline
```spl
index=* (event_type="privilege_change" OR event_type="malware_alert")
| table timestamp user source_ip host event_type country
| sort timestamp
```

## Failed-login trend
```spl
index=* event_type="login_failed"
| timechart span=1h count
```

## External successful logins
```spl
index=* event_type="login_success" country!="Internal" country!="US"
| stats count by user source_ip country host
| sort - count
```

Do not list Splunk as a skill until you actually import the CSV and run these searches yourself.
