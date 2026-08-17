from pathlib import Path
import pandas as pd
BASE=Path(__file__).resolve().parent; OUT=BASE/'outputs'; OUT.mkdir(exist_ok=True)
df=pd.read_csv(BASE/'data'/'auth_security_events.csv',parse_dates=['timestamp']); failed=df[df.event_type=='login_failed']
brute=(failed.groupby(['source_ip','user'],as_index=False).size().rename(columns={'size':'failed_logins'}).query('failed_logins >= 10').sort_values('failed_logins',ascending=False)); brute.to_csv(OUT/'brute_force_candidates.csv',index=False)
success=df[df.event_type=='login_success'][['timestamp','source_ip','user','host']]; incidents=[]
for _,row in success.iterrows():
    prior=failed[(failed.source_ip==row.source_ip)&(failed.user==row.user)&(failed.timestamp>=row.timestamp-pd.Timedelta(minutes=30))&(failed.timestamp<row.timestamp)]
    if len(prior)>=8: incidents.append({'timestamp':row.timestamp,'source_ip':row.source_ip,'user':row.user,'host':row.host,'prior_failed_logins_30m':len(prior),'severity':'high'})
pd.DataFrame(incidents).to_csv(OUT/'suspicious_success_after_failures.csv',index=False)
high=df[df.event_type.isin(['privilege_change','malware_alert'])].copy(); high.to_csv(OUT/'high_risk_events.csv',index=False)
print(f'Events analyzed: {len(df):,}'); print(f'Brute-force candidates: {len(brute)}'); print(f'Suspicious successful logins: {len(incidents)}'); print(f'High-risk events: {len(high)}')
