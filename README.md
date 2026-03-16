# Home Security Operations Lab (SOC) Project
Built a home SOC (Security Operations Center) lab using ELK (Elasticsearch, Logstash and Kibana) Stack 9.3.1 on Ubuntu. Simulated an SSH (Secure Shell) brute force attack from Kali Linux, captured traffic with Wireshark, and investigated the incident using Kibana dashboards and KQL queries.

**Author:** Siddharth Shahi  
**Platform:** Ubuntu 24.04.4 ARM64 (Victim with SIEM - Security Information and Event Management) | Kali Linux 2026.4 ARM64 (Attacker)  
**Virtualization Platform:** UTM 9.7.4 on MacBook Air M4  
**ELK (Elasticsearch, Logstash, Kibana) Stack Version:** 9.3.1  

---

## Table of Contents

1. [Overview](#overview)
2. [Lab Setup](#lab-setup)
3. [Task 1 — Setting Up the ELK Stack SIEM](#task-1--setting-up-the-elk-stack-siem)
4. [Task 2 — Running the Attack and Analyzing Traffic](#task-2--running-the-attack-and-analyzing-traffic)
5. [Task 3 — Threat Hunting](#task-3--threat-hunting)
6. [What I Found](#what-i-found)
7. [What I'd Fix](#what-id-fix)

---

## Overview

I made this project to practically learn how an SOC works in practice. I wanted to set up a real SIEM, run an attack, capture the traffic, and then go through the logs to figure out what happened and when.

I used two VMs on my MacBook: One Ubuntu machine running the ELK Stack as the victim, and a Kali Linux machine as the attacker. Running everything locally made it easy to test and redo things when needed.

---

## Lab Setup

| Component | Details |
|---|---|
| Victim VM (Virtual Machine) | Ubuntu 24.04.4 ARM64 |
| Attacker VM (Virtual Machine) | Kali Linux 2026.4 ARM64 |
| Hypervisor | UTM 9.7.4 |
| Host Machine | MacBook Air M4 |
| Network Mode | Bridged |
| Victim IP | 172.20.10.4 |
| Attacker IP | 172.20.10.3 |
| ELK Stack Version | 9.3.1 |

I set both VMs to bridged networking so they could talk to each other. I confirmed it was working by pinging between them before starting anything.

---

## Setting Up the ELK Stack SIEM

### Installing ELK Stack

I installed Elasticsearch, Logstash, and Kibana 9.3.1 on the Ubuntu VM using: sudo apt install "xyz".

### Setting Up Logstash

I created a pipeline config file at `/etc/logstash/conf.d/syslog.conf` to read logs from `/var/log/auth.log` and `/var/log/syslog`. 

Here's what I pulled out of each log line:

- `timestamp` — when it happened
- `host_name` — which machine logged it
- `program` — what process logged it (usually sshd)
- `pid` — process ID
- `log_message` — the actual log text
- `src_ip` — IP address the SSH connection came from
- `src_port` — port it came from
- `protocol` — connection type (ssh2)

**Grok pattern I used:**
```
%{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:host_name} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{DATA:log_message} from %{IP:src_ip} port %{NUMBER:src_port} %{WORD:protocol}
```

Everything gets stored in Elasticsearch under `soc-logs-YYYY.MM.dd`. After the first run, I had over 79,000 log entries indexed.

### Kibana

I created a Data View in Kibana called **SOC Logs**, pointed it at `soc-logs-*`, and set `@timestamp` as the time field. After that I could start searching and building charts.

### The Dashboard

I built a dashboard called **SOC Monitoring Dashboard** with three panels:

| Panel | Type | What it shows |
|---|---|---|
| Failed SSH Logins | Bar Chart | Failed SSH login attempts over time |
| Top Source IPs | Table | Top 5 IPs trying to connect |
| Authorization Activity Timeline | Area Chart | All auth log activity over time |

**Screenshot demonstrating the SOC Monitoring Dashboard with Failed SSH Logins, Top Source IPs and Authorization Activity Timeline:**

![](https://github.com/SiddharthShahi/images/blob/main/SOC%20Monitoring%20Dashboard.png)

The dashboard shows two clear spikes in failed SSH logins: one on March 8 and one on March 9 - both from `172.20.10.3`, the attacker machine: Kali Linux. That IP alone is the cause for 4,122 failed attempts.

---

## Running the Attack and Analyzing Traffic

### The Attack

I used Hydra on the Kali machine to brute force SSH on the Ubuntu machine. I targeted the root account using the built in rockyou wordlist in Hydra.

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://172.20.10.4
```

**Attack details:**

| What | Value |
|---|---|
| Target | ssh://172.20.10.4:22 |
| Username | root |
| Wordlist | rockyou.txt (14,344,399 passwords) |
| Speed | ~264 attempts/min |
| Parallel connections | 16 |

I ran it for about 1-2 minutes then stopped it. It didn't manage to penetrate the Ubuntu machine.

**Screenshot demonstrating Hydra running (joel is my username on the attacker machine):**

![](https://github.com/SiddharthShahi/images/blob/main/Hydra%20Attack.png)

### Wireshark Capture

While Hydra was running, I had Wireshark open on the Ubuntu machine capturing traffic on the network interface enp0s1. I used `tcp.port == 22` as a display filter to see only SSH traffic.

The capture showed a huge number of SYN packets from `172.20.10.3` going to port 22 on `172.20.10.4`, one after another. Each SYN is Hydra opening a new connection to try another password. The rapid pattern across multiple source ports tells us that it's running parallel connections, not one at a time.

**Packet details:**

- Source: `172.20.10.3` → Destination: `172.20.10.4`
- Port: 22 (SSH)
- TCP flag: `0x002` (SYN)
- Many different source ports - parallel connections
- 4,619 packets total, 183 showing with SYN-only filter

**Screenshot demonstrating Wireshark depicting Source IP, Destination IP, Attack Destination Port and Repeated SYN Flood pattern:**

![](https://github.com/SiddharthShahi/images/blob/main/Wireshark%20Demonstration.png)

### Incident Timeline in Kibana

After the attack I went into Kibana and searched the logs to build a timeline of what happened:

```
src_ip: "172.20.10.3" AND log_message: *Failed password*
```

**Results:**

| Field | Value |
|---|---|
| Total events | 1,266 |
| Source IP | 172.20.10.3 |
| Account targeted | root |
| When | March 9, 2026 @ 16:00 — 16:05 |
| Service | sshd |

The whole attack happened in about 5 minutes around 16:00 (4:00 PM).

**Screenshot demonstrating the SIEM Incident Timeline showing the total number of logged events, Source IP, account targeted, date and time and the service used:**

![](https://github.com/SiddharthShahi/images/blob/main/SIEM%20Incident%20Timeline.png)

### How It All Lines Up

| Evidence | What it showed |
|---|---|
| Wireshark | SYN flood from 172.20.10.3, lots of parallel connections to port 22 |
| SIEM logs | 1,266 failed SSH attempts for root from the same IP |
| Hydra terminal | 264 tries/min, 14.3M password list |

All three matched - same IP, same port, same time window. The Wireshark capture shows it at the packet level, and the SIEM shows it at the log level. Together they tell the full intrusion story.

---

## Threat Hunting

Once the attack data was in the SIEM, I ran three searches to understand what really happened and whether anything got missed.

### Hunt 1: How Intrusive Was the Brute Force?

**Query:**
```
log_message: *Failed password for*
```
**Time range:** Last 7 days

I ran this to see the full volume across both attack sessions (March 8 and March 9).

**What I found:**

- **4,122 failed login attempts** total
- Every single one was targeting **root**
- All from `172.20.10.3`
- Different source ports each time - confirms parallel connections
- Two spikes in the chart, one for each attack session

**Screenshot demonstrating repeated failed login attempts:**

![](https://github.com/SiddharthShahi/images/blob/main/Repeated%20Failed%20Logins%20Kibana.png)

High volume, fully automated, only targeting root.

---

### Hunt 2: Did the Attack Actually Work?

**Query:**
```
log_message: "Accepted password" OR log_message: "Accepted publickey"
```
**Time range:** Last 7 days

This was the most important check, did any login actually go through?

**What I found:**

- 3 accepted password events
- All for user **joel**, not root
- Time: **March 8 @ 17:06:45** — 7 minutes before Hydra started at 17:13
- Source IP: 172.20.10.3 — but this was me logging in manually before running the attack

So no, the brute force didn't work. Those 3 logins were my personal attempts before I started the Hydra attack.

**Screenshot demonstrating accepted password SSH attemtps:**

![](https://github.com/SiddharthShahi/images/blob/main/Successful%20SSH%20Attempt.png)

---

### Hunt 3: Did Anything Else Happen?

**Query:**
```
src_ip: "172.20.10.3" AND NOT log_message: *Failed password*
```
**Time range:** Last 7 days

I wanted to see if there was anything from the attacker IP that wasn't just failed password attempts like a reverse shell or something unexpected.

**What I found:**

- 540 more events from `172.20.10.3`
- All of them said: `error: maximum authentication attempts exceeded for root from 172.20.10.3`
- That's just sshd closing the connection after too many failed attempts per session
- No reverse shells, no weird outbound traffic, nothing unusual

**Screenshot examining events other than authentication attempts:**

![](https://github.com/SiddharthShahi/images/blob/main/Brute%20Force%20Failed.png)

The attack was completely contained. sshd kept cutting off the connections and the attacker never got past the login screen.

---

## What I Found

| # | Finding | Severity | Result |
|---|---|---|---|
| 1 | SSH brute force from 172.20.10.3 | High | Contained, no breach |
| 2 | 4,122 failed attempts targeting root | High | All failed |
| 3 | sshd auth limit hit 540 times | Medium | Working as expected |
| 4 | 3 legit SSH logins before the attack (user: joel) | Info | Confirmed as mine |
| 5 | No successful brute force login | — | Confirmed |
| 6 | No reverse shell or unusual traffic | — | Confirmed |

---

## What I would Change/Fix 

Based on what I saw during this project, here's what I would change on a real system:

**1. Turn off root SSH login: **
Root shouldn't be reachable over SSH at all. This can be prevented by adding the following line in `/etc/ssh/sshd_config`:
```
PermitRootLogin no
```

**2. Use SSH keys instead of passwords: **
Password-based SSH can be a security vulnerability. If only key-based login is allowed, brute forcing passwords becomes impossible. We can add the following line in `/etc/ssh/sshd_config`:
```
PasswordAuthentication no
```

**3. Set up fail2ban: **
fail2ban would have blocked `172.20.10.3` after the first few failed attempts. The whole attack would have been stopped in seconds instead of running for minutes.

**4. Limit SSH access by IP: **
Use a firewall to only allow SSH connections from trusted IPs. Untrusted machines should not be allowed SSH access.

**5. Change the SSH port: **
Changing the SSH port from 22 will cut down on random automated scanning hitting the machine.

**6. Add alerting to the SIEM: **
The SIEM had all the data to detect this attack, but I only found it because I was actively looking. Setting up an alert that triggers when a single IP fails to log in more than, say, 10 times in a minute would catch this automatically.

---

*This is part of my personal cybersecurity portfolio. Everything was tested in my own isolated lab environment.*
