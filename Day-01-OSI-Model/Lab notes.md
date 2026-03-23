
# Lab Notes — Real tcpdump Output

## DNS Capture Analysis

### Raw Output
<img width="1920" height="1080" alt="tcpdunp capture" src="https://github.com/user-attachments/assets/7165dd61-d4cc-453a-8ab9-95da22b73e79" />


### Analysis
NXDomain: 10.0.2.3 responded — domain doesn't exist
PTR record: IP 10.0.2.15 → hostname ubuntuopenfhe
TXT query: google.com → 13 TXT records returned
SPF record visible: v=spf1 include:_spf.google.com ~all

### SOC Interpretation
Traffic is clean baseline — no indicators of compromise.
TXT query pattern matches DNS tunneling technique
but domain (google.com) is trusted — not suspicious.
Same pattern on unknown domain = HIGH alert.
```
