# Day 1 — OSI Model + Layer 7 Application Layer
The OSI (Open Systems Interconnection) model is a conceptual framework used to understand how data moves across a network. Think of it as a universal language for computer networking, breaking the complex process of communication into seven distinct layers

## Date
23 March 2026

## What I Learned

### OSI Model
7-layer framework standardizing network communication.
Each layer has specific protocols and attack vectors.

| Layer | Name | Attack | Detection |
|-------|------|--------|-----------|
| 7 | Application | DNS Tunneling, HTTP C2, Phishing | Query length rules, beaconing detection |
| 6 | Presentation | SSL Stripping, Encrypted C2 | SSL Inspection |
| 5 | Session | Session Hijacking, Pass-the-Hash | Impossible travel alerts |
| 4 | Transport | Port Scan, SYN Flood | Connection rate monitoring |
| 3 | Network | IP Spoofing, Ping Sweep | ICMP rate rules |
| 2 | Data Link | ARP Poisoning, MITM | Duplicate ARP detection |
| 1 | Physical | Evil Twin, Keylogger | WIDS, USB monitoring |

## Layer 7 Deep Dive — Real Attacks
## Layer 7 Application layer
Layer 7 is the only layer that directly interacts with the software you use. It is the "top" of the stack and provides the protocols that allow user-facing software to send and receive information.

How it works: If you want to send an email, your email client (the app) talks to Layer 7. Layer 7 then identifies whether the network is available, authenticates the user, and initiates the data transfer process. It’s essentially the "interface" between the human-facing software and the technical network stack below it.

## Key Functions of the Application Layer
**Resource Sharing:** It allows software to access remote resources, like a file on a server or a shared printer.

**Service Advertisement:** It helps devices tell the rest of the network what services they offer (e.g., "I am a web server").

**Authentication:** It manages user logins and ensures the person sending the data is who they say they are.

**Error Handling:** It alerts the user if a network request fails at the software level (like a "404 Not Found" error).
 
### Common Layer 7 Protocols:
| Protocol | Full Name | Purpose |
| :--- | :--- | :--- |
| **HTTP/S** | Hypertext Transfer Protocol | Web browsing and API communication |
| **DNS** | Domain Name System | Translating domain names to IP addresses |
| **SMTP** | Simple Mail Transfer Protocol | Sending electronic mail (Emails) |
| **SSH** | Secure Shell | Secure remote login to systems |

## 🛡️ Security Concepts & Attack Analysis

### 1. DNS Tunneling
* **Concept:** A technique used to exfiltrate data or establish a Command & Control (C2) channel by hiding data within standard DNS queries.
* **Mechanism:** Data is encoded as subdomains (e.g., `secret-data.attacker.com`). Since firewalls usually allow DNS traffic (Port 53), this bypasses traditional security perimeters.
* **Detection Strategy:**
    * **Query Length:** Look for DNS queries exceeding **50 characters**.
    * **Entropy:** High count of unique or random-looking subdomains.
* **MITRE ATT&CK:** [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

For visual representaion view this source: **<img width="500" height="275" alt="DNS Tunneling " src="https://github.com/user-attachments/assets/2e5c2b1f-ec58-44e7-8dc0-4c49cbba9d57" />**
### 2. HTTP C2 Beaconing
* **Concept:** Malware communicating with a Command & Control (C2) server at regular intervals to receive instructions.
* **Mechanism:** Analysts check for **Jitter** (timing variation). If Jitter is near zero, it indicates machine behavior (malware) rather than human activity.
* **Detection Strategy:**
    * **Consistency:** Standard Deviation (stdev) of intervals **< 5 seconds**.
    * **Volume:** Connection count **> 10** in a short window.
* **MITRE ATT&CK:** [T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

### 3. Phishing
* **Concept:** Deceiving users via fake emails to steal credentials or deliver malicious payloads.
* **IOCs (Indicators of Compromise):**
    * **Domain Age:** Newly registered sender domains.
    * **Header Mismatch:** "From" address does not match the "Reply-To" address.
    * **Language:** High-pressure or urgent tone to trigger fast action.
    * **MITRE ATT&CK:** T1566.001 / T1566.002
* **Investigation Tools:** * [VirusTotal](https://www.virustotal.com/)
    * [URLScan.io](https://urlscan.io/)
    * [MXToolbox](https://mxtoolbox.com/)
    * [AbuseIPDB](https://www.abuseipdb.com/)
      


## Splunk Detection Rules Written

### DNS Tunneling Detection
```spl
index=dns_logs
| eval query_length = len(dns_query)
| where query_length > 50
| stats count, dc(dns_query) as unique_queries by src_ip
| where unique_queries > 20
| eval risk = "DNS_TUNNELING_SUSPECTED"
```

### HTTP Beaconing Detection
```spl
index=web_proxy_logs
| streamstats window=2 latest(_time) as t2 earliest(_time) as t1 by src_ip, dest_domain
| eval interval = t2 - t1
| stats stdev(interval) as jitter, count by src_ip, dest_domain
| where jitter < 5 AND count > 10
| eval risk = "BEACONING_SUSPECTED"
```

## Practical Labs Completed

### tcpdump Output Analysis (Real capture)
Captured DNS traffic on Ubuntu VM. Identified:
- NXDomain response — non-existent domain query
- PTR record — reverse DNS lookup (IP to hostname)
- TXT record query — dig TXT google.com (13 records returned)
- Key insight: TXT queries = DNS tunneling vector

### Commands Run
**Ubuntu VM:**
sudo tcpdump -i any port 53 -v
sudo tcpdump -i any port 80 -A -c 20
sudo tcpdump -i any arp -v -c 10
dig TXT google.com

**Windows Host:**
nslookup google.com
arp -a
netstat -an
tracert google.com

### Wireshark Filters Used
dns — DNS traffic
http — HTTP traffic
arp — ARP packets
tcp.flags.syn==1 and tcp.flags.ack==0 — SYN scan detection

## Key Takeaways
1. Every OSI layer has a specific attack vector
2. DNS tunneling uses TXT records and long subdomains
3. Beaconing = low jitter, regular intervals = machine behavior
4. Normal traffic baseline knowing is critical before detecting anomalies

## Real World Connection
SolarWinds 2020: DNS tunneling used for data exfiltration — exactly Layer 7 T1071.004
