# Home Security Lab 01 — Linux Services, Network Traffic and Log Correlation

**Project type:** Home lab / SOC analyst practice  
**Date:** 1 October 2026 (evidence collection)  
**Lab setup and investigation by:** Szymon Orzeł (yngxlr8)  

## 1. Overview

In this project, I investigated two services running on an Ubuntu Server virtual machine: **OpenSSH (TCP/22)** and **nginx (TCP/80)**. I used Kali Linux to check network reachability, enumerate exposed services, generate successful and failed SSH authentication events, and make HTTP requests. I then compared the client-side observations with server processes, listening sockets, application logs, and a Wireshark packet capture.

The goal was to build a verifiable evidence chain:

**Service configuration → running process → listening socket → remote client activity → network packets → server-side logs.**

All testing was performed against my own virtual machines in an authorized home lab. This project was a visibility and investigation exercise, **not a vulnerability exploitation or intrusion test**.

## 2. Lab environment

| System                    | Role                                                     | Host-only IP        | Interface  |
| ------------------------- | -------------------------------------------------------- | ------------------- | ---------- |
| Ubuntu host               | Runs VirtualBox and provides the host-side lab interface | `192.168.56.1/24`   | `vboxnet0` |
| Kali Linux (`kali`)       | Test client, Nmap scanner, packet capture                | `192.168.56.102/24` | `eth1`     |
| Ubuntu Server (`userver`) | Investigated endpoint; SSH and HTTP server               | `192.168.56.101/24` | `enp0s8`   |

The relevant traffic used the VirtualBox **Host-only network `192.168.56.0/24`**. The VMs also had separate NAT adapters configured; those adapters were not the path used for the lab tests described here. A Host-only network provides a controlled segment, but it should not be treated as complete isolation from the Ubuntu host.

```text
                   Ubuntu host (VirtualBox)
                   vboxnet0: 192.168.56.1
                             |
               Host-only network 192.168.56.0/24
                       /               \
                      /                 \
           Kali Linux                 Ubuntu Server
           eth1: .102                 enp0s8: .101
           test client                sshd: TCP/22
           packet capture             nginx: TCP/80
```

**Evidence:** [Kali IP configuration](screenshots/screenshot_01.png) · [Ubuntu Server IP configuration](screenshots/screenshot_02.png)

**Tools and evidence sources:** `ip`, `systemctl`, `ps`, `ss`, `ping`, Nmap, `curl`, `journalctl`, nginx `access.log`, and Wireshark.

## 3. Investigation method

I followed the same process for each service:

1. **Establish local state:** identify the service, related process, and listening socket on Ubuntu Server.
2. **Check the remote perspective:** verify basic connectivity and scan only the known Ubuntu Server IP from Kali.
3. **Generate controlled events:** attempt SSH authentication and request existing/non-existing HTTP resources.
4. **Collect evidence:** inspect SSH journal entries, nginx access logs, and HTTP/TCP traffic captured on Kali `eth1`.
5. **Correlate carefully:** compare IP addresses, ports, requests, response codes, user names, and recorded times; document what the evidence cannot prove.

The screenshots are the preserved evidence for this public write-up. The original live journal, nginx log, and packet capture are **not published as raw evidence files** in this repository.

## 4. Findings

### A. Local services, processes, and listening ports

On Ubuntu Server, `systemctl status ssh` showed `ssh.service` **active (running)** with an `sshd` listener (PID **1624**). Its unit was marked **disabled** for direct automatic startup and the status referenced `ssh.socket` as a trigger. This illustrates that **current service state and enablement are separate properties**.

`systemctl status nginx` showed `nginx.service` **active (running)** and **enabled**. Its master process had PID **1058**, with worker processes **1059** and **1060**. The process listing showed the master running as `root` and workers as `www-data`.

`sudo ss -tulpn` confirmed listening TCP sockets:

| Local socket | Protocol | Associated process | What it establishes |
|---|---|---|---|
| `0.0.0.0:22` | TCP | `sshd` (and `systemd` in the socket listing) | SSH was listening on local IPv4 addresses. |
| `0.0.0.0:80` | TCP | `nginx` | HTTP was listening on local IPv4 addresses. |
| `[::]:22`, `[::]:80` | TCP | SSH and nginx | Corresponding IPv6 listeners were also present. |

`0.0.0.0` means **all local IPv4 addresses**, not that the service is automatically reachable from every network. A listening socket is local evidence; an external connectivity test is still needed.

**Evidence:** [SSH service](screenshots/screenshot_03.png) · [Listening sockets (`ss`)](screenshots/screenshot_04.png) · [SSH process](screenshots/screenshot_05.png) · [nginx service](screenshots/screenshot_06.png) · [nginx processes](screenshots/screenshot_07.png)

### B. Remote connectivity and Nmap service detection

From Kali, I tested the Ubuntu Server Host-only address:

```bash
ping -c 2 192.168.56.101
nmap -sV -p 22,80 192.168.56.101
```

The ping test received **2/2 ICMP echo replies** with **0% packet loss**. This established that the host answered ICMP during the test; ping alone does not show whether SSH or HTTP is available.

Nmap reported the host up and found both selected ports open:

| Port | Nmap state | Detected service/version |
|---|---|---|
| `22/tcp` | `open` | OpenSSH `10.2p1` (`Ubuntu 2ubuntu3.6`) |
| `80/tcp` | `open` | nginx `1.28.3` (Ubuntu) |

The scan also displayed the virtual NIC MAC address `08:00:27:32:7B:15`, consistent with the VirtualBox lab context. Version strings are **Nmap's detection results**, not proof of an exhaustive server inventory or a vulnerability.

**Assessment:** `ss` answered *which local processes were listening*; Nmap answered *what Kali could reach and identify remotely*. The results agreed in this configuration. They could differ because of firewall rules, interface binding, routing, or changes in service state.

**Evidence:** [Ping](screenshots/screenshot_08.png) · [Nmap scan](screenshots/screenshot_09.png) · [Server sockets](screenshots/screenshot_04.png)

### C. SSH authentication: failed attempts followed by success

I deliberately entered incorrect credentials for the lab account `analyst`, then authenticated successfully. Ubuntu Server's SSH journal contained the following sequence on **1 October 2026**:

| Time shown by `journalctl` | Source | Observation |
|---|---|---|
| `19:35:47` | `192.168.56.102:47726` | `Failed password for analyst` |
| `19:35:50` | `192.168.56.102:47726` | A second `Failed password for analyst` |
| `19:35:55` | `192.168.56.102:47726` | `Accepted password for analyst` |
| `19:35:55` | SSH/PAM | Session opened for `analyst` |

The entries were obtained from the SSH unit journal, for example:

```bash
journalctl -u ssh --since "20 minutes ago"
```

The journal records identify a **target account**, **source IP**, **client's temporary TCP port**, **event time**, and **authentication result**. The port `47726` is a client-side ephemeral port, **not the SSH service port** (the server listened on TCP/22). The failed attempts and subsequent success are visible under the same source port in this captured sequence.

**Assessment:** The sequence is consistent with my controlled test. These records do **not** by themselves prove who was physically operating Kali or establish a brute-force attack. A single source performing a few failed attempts is an investigation lead, not automatic evidence of compromise.

**Evidence:** [SSH authentication journal](screenshots/screenshot_11.png)

### D. HTTP requests, nginx responses, and visible scanning artifacts

From Kali, I requested the default web page and a non-existent path:

```bash
curl http://192.168.56.101/
curl http://192.168.56.101/nie-istnieje
```

The first command displayed nginx's default HTML page. The second displayed nginx's HTML **404 Not Found** page. The server access log recorded:

| Time in nginx log (`+0000`) | Client | Request | Status | Body bytes sent | User-Agent |
|---|---|---|---|---:|---|
| `19:35:07` | `192.168.56.102` | `GET / HTTP/1.1` | `200` | `615` | `curl/8.20.0` |
| `19:35:11` | `192.168.56.102` | `GET /nie-istnieje HTTP/1.1` | `404` | `162` | `curl/8.20.0` |

A **404 response can include a response body**: in this case, the 404 HTML page accounted for **162 body bytes** in the nginx log. The access log shows metadata about the response, not the complete HTML content.

The same screenshot also contains requests with a User-Agent identifying **Nmap Scripting Engine**, including probes for paths such as `/sdk`, `/evox/about`, and `/HNAP1`. These requests returned `404` in the displayed log entries.

**SOC relevance:** Service identification and reconnaissance can leave **application-layer artifacts**. An analyst reviewing repeated unusual HTTP paths should investigate the source, request sequence, User-Agent, and surrounding context. A User-Agent is client-supplied and can be spoofed; these entries are consistent with the Nmap activity in this lab but are not a signature of an attack on their own.

**Evidence:** [curl output](screenshots/screenshot_10.png) · [nginx access log, including Nmap-related probes](screenshots/screenshot_12.png) · [Nmap scan](screenshots/screenshot_09.png)

### E. Packet analysis: the HTTP connection in Wireshark

I captured the Kali-to-Ubuntu Server HTTP exchange in **Wireshark on Kali `eth1`**. The display filter in the preserved screenshot was:

```text
ip.addr == 192.168.56.102
```

The capture shows the TCP connection **`192.168.56.102:37004 → 192.168.56.101:80`** and its application exchange:

| Frame | Direction | Observation |
|---|---|---|
| 1 | Kali → Ubuntu Server | TCP `SYN` |
| 2 | Ubuntu Server → Kali | TCP `SYN, ACK` |
| 3 | Kali → Ubuntu Server | TCP `ACK`; three-way handshake completed |
| 4 | Kali → Ubuntu Server | HTTP `GET / HTTP/1.1` |
| 5 | Ubuntu Server → Kali | TCP acknowledgment of request data |
| 6 | Ubuntu Server → Kali | HTTP `200 OK` response |
| 7 | Kali → Ubuntu Server | TCP acknowledgment of response data |
| 8–10 | Both directions | TCP `FIN/ACK` and final acknowledgment; graceful close |

The request segment contained **78 bytes of TCP payload**, reflected in the server's acknowledgment `Ack=79` with Wireshark's relative sequence numbers. The HTTP response occupied **862 bytes of TCP payload** in the captured segment; this includes HTTP response headers and the body, so it is not the same measure as the nginx log's **615 body bytes** for a successful default-page response.

**Assessment:** The capture independently demonstrates the TCP handshake, an HTTP request, a successful HTTP response, and connection closure. The screenshot uses **relative capture time** rather than a visible wall-clock timestamp; it therefore cannot be matched conclusively to one specific `GET /` access-log entry when multiple such requests exist. It also does not show the SSH authentication exchange.

**Evidence:** [Wireshark TCP/HTTP exchange](screenshots/screenshot_13.png) · [nginx log](screenshots/screenshot_12.png)

## 5. SOC assessment

The evidence supports the following conclusions:

- **OpenSSH and nginx were running and listening** on the Ubuntu Server during local observation.
- **Kali could reach both TCP services** at the time of the remote Nmap scan.
- **Two failed SSH password attempts were followed by a successful authentication** to the lab account `analyst` from Kali's Host-only IP.
- **The HTTP server returned both `200` and `404` responses** to deliberate curl requests.
- **The packet capture confirms a completed TCP connection and HTTP transaction** between Kali and Ubuntu Server.
- **nginx recorded additional HTTP probes consistent with active service reconnaissance.**

These observations were generated by **authorized lab activity**. No unauthorized access or exploitation was established. A repeated login failure, unusual URL, or `open` port should not be labelled malicious without more context.

## 6. Detection opportunities (ideas, not implemented rules)

| Activity to watch | Potential evidence source | Analyst's first questions |
|---|---|---|
| Multiple failed SSH passwords followed by a successful login | SSH journal / authentication logs | Same user and source? Same time window? Expected access? How many attempts? |
| SSH access from an unexpected address | SSH journal plus network inventory | Is the IP assigned to a known host? Is this normal administration? |
| Repeated HTTP requests to unusual paths | nginx access log | Same client? Status codes? User-Agent? Pattern consistent with an approved scan? |
| Web service unexpectedly reachable from another host | Local `ss`, Nmap from an authorized test host | Which process owns the port? What interface is bound? Are firewall rules relevant? |
| HTTP application activity after a new TCP connection | Network capture plus nginx logs | Do IP, port, direction, path, response, and timestamps support a correlation? |

These are **investigation ideas only**. No SIEM, detection rule, or alerting pipeline was implemented in Lab 01. Legitimate administration, user mistakes, and authorized scans can produce the same indicators.

## 7. Evidence files and screenshot index

The screenshots below were captured during the original lab and are provided in [`screenshots/`](screenshots/). The original raw logs and PCAP were **not added to this public repository**.

| Evidence                        | Screenshot                                         | Key observation                                       |
| ------------------------------- | -------------------------------------------------- | ----------------------------------------------------- |
| Kali interface/IP               | [screenshot_01.png](screenshots/screenshot_01.png) | `eth1`, `192.168.56.102/24`                           |
| Ubuntu Server interface/IP      | [screenshot_02.png](screenshots/screenshot_02.png) | `enp0s8`, `192.168.56.101/24`                         |
| SSH service status              | [screenshot_03.png](screenshots/screenshot_03.png) | Active `ssh.service`, PID `1624`, socket trigger      |
| Ubuntu Server listening sockets | [screenshot_04.png](screenshots/screenshot_04.png) | TCP/22 `sshd`, TCP/80 nginx                           |
| SSH process listing             | [screenshot_05.png](screenshots/screenshot_05.png) | Running `sshd` listener                               |
| nginx service status            | [screenshot_06.png](screenshots/screenshot_06.png) | Active and enabled; PID `1058`                        |
| nginx process listing           | [screenshot_07.png](screenshots/screenshot_07.png) | Master and worker processes                           |
| Ping from Kali                  | [screenshot_08.png](screenshots/screenshot_08.png) | 2/2 ICMP replies                                      |
| Nmap service detection          | [screenshot_09.png](screenshots/screenshot_09.png) | Ports `22/tcp` and `80/tcp` open                      |
| HTTP requests from Kali         | [screenshot_10.png](screenshots/screenshot_10.png) | Default nginx page and 404 HTML                       |
| SSH journal                     | [screenshot_11.png](screenshots/screenshot_11.png) | Failed attempts followed by successful authentication |
| nginx access log                | [screenshot_12.png](screenshots/screenshot_12.png) | HTTP 200/404 and service-detection probes             |
| Wireshark capture               | [screenshot_13.png](screenshots/screenshot_13.png) | HTTP over TCP, 3-way handshake and close              |

## 8. Limitations

- **Screenshots, not raw datasets:** the original PCAP and complete log exports are stored locally, not available in this repository.
- **Different time representations:** the nginx log uses `+0000`, Nmap displays `-0400`, and the SSH journal screenshot does not show an explicit time-zone offset. The Wireshark screenshot displays only time relative to the beginning of its capture. A fully normalized, packet-to-log timeline was therefore not established.
- **Point-in-time observations:** `systemctl`, `ps`, `ss`, ping, and Nmap describe conditions when executed. They do not provide a continuous history.
- **Attribution and intent:** IP addresses, account names, and User-Agent strings identify recorded context, not the physical operator or an attacker's intent.
- **Service version inference:** Nmap service/version detection is an observation from remote probes, not a guarantee of software identity or vulnerability status.

## 9. Lessons learned

This first investigation taught me to:

- Explain the difference between a **program, process, service, and listening socket**.
- Distinguish **local host state** (`systemctl`, `ps`, `ss`) from **remote reachability** (Nmap).
- Trace a simple network event from **client action to packet capture to server log**.
- Interpret authentication logs using **account, source IP, ephemeral port, timestamp, and result**.
- Recognize that tools such as Nmap can leave evidence in **application logs**, not only in packet captures.

The next portfolio project, **[Home Security Lab 02 — Windows Security Investigation](https://github.com/yngxlr8/Home-Security-Lab-02)**, extends this approach to Windows authentication events, PowerShell execution, scheduled tasks, and firewall evidence.
