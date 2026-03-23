# Incident Response Report: Akira Ransomware Attack
**Target:** Ashford Sterling Recruitment  
**Analyst:** Jason Stokes  
**Date of Incident:** January 27, 2026  
**Date of Report:** March 22, 2026  

---

## 1. Executive Summary
On January 27, 2026, Ashford Sterling Recruitment suffered a targeted cyberattack resulting in data theft and system encryption. The attack was attributed to the **Akira** ransomware group. 

The threat actor bypassed perimeter security by utilizing a pre-existing, unauthorized remote access tool (AnyDesk) left on an employee's workstation. After gaining entry, the attacker successfully disabled Microsoft Defender antivirus protections, stole administrator credentials, and moved laterally to a critical file server. 

Before deploying the ransomware, the attacker compressed company data for exfiltration. Finally, the attacker intentionally destroyed Windows system backups to prevent data recovery before executing the ransomware payload, which encrypted files and appended the `.akira` extension. The incident was contained to two hosts, but represents a severe compromise of internal data and infrastructure.

## 2. Attack Timeline
*All times are recorded in Coordinated Universal Time (UTC) on January 27, 2026.*

* **20:22:00** - Threat actor establishes initial access via AnyDesk and deploys the first Command and Control (C2) beacon (`wsync.exe`).
* **20:44:00** - A secondary, modified C2 beacon is deployed to maintain a stable connection to attacker infrastructure.
* **21:03:42** - Attacker successfully alters the Windows Registry (`DisableAntiSpyware`) via a batch script (`kill.bat`) to turn off Microsoft Defender.
* **22:17:00** - Network scanning and internal reconnaissance are conducted to find additional targets.
* **22:18:33** - Ransomware payload (`updater.exe`) is executed on the target server. File encryption begins and the `akira_readme.txt` ransom note is dropped.
* **22:24:09** - Sensitive data is compressed into a staging archive (`exfil_data.zip`) for exfiltration out of the network.
* **Post-Encryption** - Attacker executes a cleanup script (`clean.bat`) to delete their malicious tools and hide evidence.

---

## 3. MITRE ATT&CK Tactics and Techniques
To understand the attacker's playbook, this incident has been mapped to the industry-standard MITRE ATT&CK framework.

| Tactic | Technique ID | Technique Name | Description of Attacker Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services | Attacker used a pre-staged AnyDesk installation to enter the network. |
| **Defense Evasion** | T1562.001 | Impair Defenses | Executed `kill.bat` to modify the registry and disable Microsoft Defender. |
| **Credential Access** | T1003.001 | OS Credential Dumping | Targeted the `lsass` process to steal the server administrator password. |
| **Discovery** | T1046 | Network Service Discovery | Used Advanced IP Scanner (`scan.exe`) to find other targets on the network. |
| **Lateral Movement**| T1021.002 | SMB/Windows Admin Shares | Used stolen credentials to move from the workstation to the file server. |
| **Collection** | T1560.001 | Archive Collected Data | Compressed stolen files into `exfil_data.zip` using a staging tool (`st.exe`). |
| **Impact** | T1490 <br> T1486 | Inhibit System Recovery <br> Data Encrypted for Impact | Deleted Windows shadow copies via `vssadmin`, then deployed Akira ransomware (`updater.exe`). |

---

## 4. Indicators of Compromise (IoCs)
The following network and file-based indicators were extracted during the investigation. These can be used by security teams to block future attacks.

### Network Indicators (IPs & Domains)
| Type | Indicator | Description |
| :--- | :--- | :--- |
| **IP Address** | `88.97.164.155` | Attacker's external remote access IP |
| **IP Address** | `172.67.174.46`, `104.21.30.237` | Command & Control (C2) infrastructure |
| **Domain** | `sync.cloud-endpoint.net` | External domain used to host attacker payloads |
| **Domain** | `cdn.cloud-endpoint.net` | Domain used to stage the ransomware |
| **Domain** | `relay-0b975d23.net.anydesk.com` | Relay server used by the AnyDesk remote tool |
| **URL** | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` | Akira TOR negotiation portal |

### File Indicators (Hashes)
| Filename | SHA-256 Hash | Description |
| :--- | :--- | :--- |
| `kill.bat` | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` | Script used to disable Microsoft Defender |
| `wsync.exe` | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` | Original Command & Control beacon |
| `wsync.exe` | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` | Replacement Command & Control beacon |
| `scan.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` | Network scanner tool (Advanced IP Scanner) |
| `st.exe` | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` | Staging tool used to compress exfiltrated data |
| `updater.exe` | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` | Akira Ransomware executable |

---

## 5. Strategic Remediation Recommendations
To prevent a recurrence of this attack and harden the environment against similar threat actors, the following strategic remediations are recommended:

* **Audit and Restrict Remote Management Tools:** Implement application control to block unauthorized remote access software (e.g., AnyDesk) across the network. Only IT-approved tools should be permitted, and they must be secured behind Multi-Factor Authentication (MFA).
* **Enforce Least Privilege & System Hardening:** Revoke local administrator rights from standard user accounts to prevent unauthorized execution of evasion scripts. Apply established security baselines, such as DISA STIGs, using configuration scripts to lock down registry permissions and prevent tampering with Microsoft Defender.
* **Enable Credential Guard:** Activate Windows Defender Credential Guard to isolate the Local Security Authority Subsystem Service (LSASS) process, preventing attackers from dumping plaintext credentials from memory.
* **Implement LAPS and Network Segmentation:** Deploy the Local Administrator Password Solution (LAPS) to randomize local admin passwords across endpoints, halting lateral movement. Segment critical servers from general user workstations to limit an attacker's blast radius.
* **Deploy Immutable, Offline Backups:** Ensure that critical business data is backed up to an offline, immutable storage solution that cannot be modified or deleted via network commands (such as `vssadmin`).

---

## 6. Technical Analyst Log (Evidence & KQL Queries)
*This section contains the raw analytical findings, threat hunting logic, and KQL queries used to verify the attack path and scope the incident.*

### Baseline Investigation Start
**Analysis:** Analysis of the `DeviceProcessEvents` logs for the `DisableAntiSpyware` alert confirmed that the threat actor gained access to the endpoint `as-pc2` under the user context of `david.mitchell`. At 21:06:58 UTC on January 27, 2026, the attacker successfully executed a command using `reg.exe` to modify the registry (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`) and disable real-time antivirus protection, paving the way for further malicious activity.

**Query Used:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "DisableAntiSpyware"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
*<img width="800" alt="1" src="https://github.com/user-attachments/assets/c97f0528-fe14-4ef2-baa0-eb3c9308ffd7" />*

---

### SECTION 1: RANSOMWARE ATTRIBUTION AND IMPACT

**Cyber Range Investigation Flags:**
* **🚩 Q1 - Threat Actor:** What ransomware group is responsible? **Akira**
* **🚩 Q2 - Negotiation Portal:** What is the TOR negotiation address? **`akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`**
* **🚩 Q3 - Victim ID:** What is the company's unique ID? **`813R-QWJM-XKIJ`**
* **🚩 Q4 - Encrypted Extension:** What file extension is added to encrypted files? **`.akira`**

**Analysis:** During the initial investigation of the compromised file server, a text document named `akira_readme.txt` was discovered among the encrypted files. Reviewing the contents of this ransom note provided direct attribution for the attack, as the threat actors explicitly introduced themselves by stating, "Hi, We are Akira". The document instructed the victim to use the TOR network for negotiations using the provided ID. It also confirmed the use of AES-256 encryption, appending the `.akira` extension to all affected files across the compromised systems.

*<img width="800" alt="Ransom_Note" src="https://github.com/user-attachments/assets/c99e6723-049f-41f5-a46d-6fd926af6016" />*

---

### SECTION 2: ATTACKER INFRASTRUCTURE

**Cyber Range Investigation Flags:**
* **🚩 Q5 - Payload Domain:** What domain hosted the payloads? **`sync.cloud-endpoint.net`**
* **🚩 Q6 - Ransomware Staging:** What domain staged the ransomware? **`cdn.cloud-endpoint.net`**
* **🚩 Q7 - C2 IP Addresses:** What are the two C2 IP addresses? **`172.67.174.46, 104.21.30.237`**
* **🚩 Q8 - Remote Tool Relay:** What is the remote tool relay domain that was used? **`relay-0b975d23.net.anydesk.com`**

**Analysis:** To identify where the attacker downloaded their tools, a hunt was conducted within the `DeviceNetworkEvents` table to review external network connections initiated by PowerShell on the compromised device. The log results revealed PowerShell downloading payloads directly from the external domain `sync.cloud-endpoint.net`. Following this discovery, a pivot for the root domain `cloud-endpoint.net` revealed a secondary staging domain (`cdn.cloud-endpoint.net`). Further investigation into the initial payload domain identified the specific C2 IP addresses, while logs for `anydesk.exe` identified the attacker's remote tool relay infrastructure.

**Query Used (Payload Domain):**
```kusto
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName == "powershell.exe"
| where isnotempty(RemoteUrl)
| project Timestamp, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| sort by Timestamp asc
```
*<img width="800" alt="Q5" src="https://github.com/user-attachments/assets/99e84832-125a-42a3-b32d-5c905f9c95b9" />*

**Query Used (Ransomware Staging Domain):**
```kusto
DeviceNetworkEvents
| where RemoteUrl contains "cloud-endpoint.net"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl
| sort by Timestamp desc
```
*<img width="800" alt="Q6" src="https://github.com/user-attachments/assets/4bdc314e-fe36-49b5-b1a1-274518c4a9fc" />*

**Query Used (C2 IPs):**
```kusto
DeviceNetworkEvents
| where RemoteUrl == "sync.cloud-endpoint.net"
| distinct RemoteIP
```
*<img width="800" alt="Q7" src="https://github.com/user-attachments/assets/2b80b088-3ffb-4f2f-952c-740333394415" />*

**Query Used (Remote Tool Relay):**
```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "anydesk.exe"
| where isnotempty(RemoteUrl)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl
| sort by Timestamp desc
```
*<img width="800" alt="Q8" src="https://github.com/user-attachments/assets/d683ca2f-b8b6-4768-99a7-1e2e1b446e26" />*

---

### SECTION 3: DEFENSE EVASION

**Cyber Range Investigation Flags:**
* **🚩 Q9 - Evasion Script:** What script disabled security? **`kill.bat`**
* **🚩 Q10 - Evasion Hash:** What is the SHA256 of the script? **`0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`**
* **🚩 Q11 - Registry Tampering:** What registry value disabled Windows Defender? **`DisableAntiSpyware`**
* **🚩 Q12 - Registry Timestamp:** What time was the registry modified? **`21:03:42`**

**Analysis:** To understand how the threat actor bypassed security controls, an analysis of the initial Microsoft Defender alert was conducted. By querying `DeviceProcessEvents` for commands associated with disabling antivirus protections, the logs confirmed that the attacker executed a batch script named `kill.bat`. The logs confirmed the script was dropped in the `C:\ProgramData\` directory. To verify the exact system changes, `DeviceRegistryEvents` were reviewed, confirming the script successfully modified the registry at exactly 21:03:42 UTC by creating the value `DisableAntiSpyware` and setting its data to 1, effectively disabling Microsoft Defender's protections.

**Query Used (Process Execution):**
```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "DisableAntiSpyware"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
*<img width="800" alt="Q9" src="https://github.com/user-attachments/assets/bd93a42d-356d-432d-8e3c-fef9607e1420" />*
 
**Query Used (File Hash):**
```kusto
DeviceFileEvents
| where FileName == "kill.bat"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```
*<img width="800" alt="Q10" src="https://github.com/user-attachments/assets/cb691c4d-42bf-4618-9ee6-3db94cc10500" />*

**Query Used (Registry Value):**
```kusto
DeviceRegistryEvents
| where DeviceName == "as-pc2"
| where RegistryKey contains "Windows Defender"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
*<img width="800" alt="Q11" src="https://github.com/user-attachments/assets/afd3bafa-4956-4345-b23c-d7ac86c3c168" />*

**Query Used (Timestamp):**
```kusto
DeviceRegistryEvents
| where DeviceName == "as-pc2"
| where RegistryValueName == "DisableAntiSpyware"
| project DeviceName, RegistryValueName, ExactTimeUTC = format_datetime(Timestamp, 'HH:mm:ss')
```
*<img width="800" alt="Q12" src="https://github.com/user-attachments/assets/559bf042-13a8-49ee-bc51-a7d9ddf81fb6" />*

---

### SECTION 4: CREDENTIAL ACCESS

**Cyber Range Investigation Flags:**
* **🚩 Q13 - Process Hunt:** What command was used? **`tasklist | findstr lsass`**
* **🚩 Q14 - Credential Pipe:** What named pipe was accessed? **`\Device\NamedPipe\lsass`**

**Analysis:** To determine how the attacker targeted credentials, process execution logs (`DeviceProcessEvents`) were reviewed for built-in discovery commands. A search for `tasklist` revealed that the attacker executed the command `cmd.exe /c "tasklist | findstr lsass"`. Because the attacker specifically targeted the `lsass` process, `DeviceEvents` were queried for named pipe connections containing "lsass". The results successfully identified multiple connections, confirming the attacker accessed the `\Device\NamedPipe\lsass` pipe to facilitate credential theft.

**Query Used (Process Hunt):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where ProcessCommandLine contains "tasklist"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```
*<img width="800" alt="Q13" src="https://github.com/user-attachments/assets/edaef744-dcec-4133-902c-62c79aac38d9" />*


**Query Used (Named Pipe):**
```kusto
DeviceEvents
| where DeviceName == "as-pc2"
| where ActionType == "NamedPipeEvent"
| where AdditionalFields contains "lsass"
| project TimeGenerated, DeviceName, ActionType, AdditionalFields
```
*<img width="800" alt="Q14" src="https://github.com/user-attachments/assets/06d81708-4e3e-42c3-816e-e535d26aa0db" />*

---

### SECTION 5: INITIAL ACCESS PATHWAY

**Cyber Range Investigation Flags:**
* **🚩 Q15 - Remote Access Tool:** What remote access tool was used? **`AnyDesk`**
* **🚩 Q16 - Suspicious Execution Path:** What user was compromised on AS-PC2? *(Note: Expected path output)* **`C:\Users\Public\`**
* **🚩 Q17 - Attacker IP:** What is the attacker's external IP? **`88.97.164.155`**
* **🚩 Q18 - Compromised User:** What user was compromised on AS-PC2? **`david.mitchell`**

**Analysis:** To identify the pre-staged remote access tool used by the threat actor, process execution logs were reviewed. The attacker utilized a legitimate remote management application (AnyDesk) to maintain persistent, unauthorized access to the system. `DeviceProcessEvents` confirmed that the threat actor utilized the hijacked account `david.mitchell` to launch the application. Furthermore, the tool was executed from a highly suspicious directory (`C:\Users\Public\`), bypassing standard installation paths to evade detection. Subsequent direct connections were established with an external, unassociated IP address (`88.97.164.155`).

**Query Used (AnyDesk Execution):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where FileName contains "anydesk"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| sort by Timestamp asc
```
*<img width="800" alt="Q15" src="https://github.com/user-attachments/assets/b7c58ba4-a3c3-4483-9bd8-08eac1ef1d2e" />*

**Query Used (Execution Path & User):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where FileName =~ "anydesk.exe"
| project Timestamp, AccountName, FolderPath
| sort by Timestamp asc
```
*<img width="800" alt="Q16" src="https://github.com/user-attachments/assets/fe10ca80-3ea2-4491-9a4f-2c352fee090c" />*

**Query Used (Initial Compromised Account):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where FileName =~ "anydesk.exe"
| summarize by AccountName
```
*<img width="800" alt="Q18" src="https://github.com/user-attachments/assets/9a56404f-b715-4a38-8aa6-81c4deb09d6a" />*

**Query Used (Attacker IP):**
```kusto
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIPType == "Public"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort
| sort by Timestamp asc
```
*<img width="800" alt="Q17" src="https://github.com/user-attachments/assets/8a9d3c39-605b-4153-a091-69c7059c7e59" />*

---

### SECTION 6: COMMAND & CONTROL (C2)

**Cyber Range Investigation Flags:**
* **🚩 Q19 - Primary Beacon:** What new C2 beacon was deployed? **`wsync.exe`**
* **🚩 Q20 - Beacon Location:** What directory was the new beacon deployed to? **`C:\ProgramData\`**
* **🚩 Q21 - Beacon Hash:** What is the SHA256 of the original beacon? **`66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`**
* **🚩 Q22 - Beacon Creation:** What is the SHA256 of the replacement beacon on AS-PC2? **`0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`**

**Analysis:** To find the Command and Control (C2) beacon, file creation logs were searched. By filtering for files created by PowerShell, a highly suspicious file named `wsync.exe` was found deployed into the hidden `C:\ProgramData\` folder. Following the failure of the initial beacon at 20:22 UTC, the threat actor deployed a secondary, modified version at 20:44 UTC. Both hashes were successfully recovered from the file modification logs.

**Query Used (Beacon Creation & Location):**
```kusto
DeviceFileEvents
| where DeviceName == "as-pc2"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, InitiatingProcessFileName, FileName, FolderPath
| sort by Timestamp desc
```
*<img width="800" alt="Q19" src="https://github.com/user-attachments/assets/f01bdbed-ca8e-4649-8e3d-5d66536a074e" />*

**Query Used (Beacon Hashes):**
```kusto
DeviceFileEvents
| where DeviceName == "as-pc2"
| where FileName =~ "wsync.exe"
| project Timestamp, ActionType, FileName, SHA256
| sort by Timestamp asc
```
*<img width="800" alt="Q21" src="https://github.com/user-attachments/assets/b6fa7076-d90e-4712-91a6-3265fe4b49cf" />*

*<img width="800" alt="Q22" src="https://github.com/user-attachments/assets/e3c272cd-7b4c-493a-9449-0a027c02ecca" />*

---

### SECTION 7: RECONNAISSANCE

**Cyber Range Investigation Flags:**
* **🚩 Q23 - Scanner Tool:** What scanner tool was used? **`scan.exe`**
* **🚩 Q24 - Scanner Hash:** What is the SHA256 of the scanner tool? **`26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`**
* **🚩 Q25 - Scanner Execution:** What arguments were passed to the scanner on execution? **`/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`**
* **🚩 Q26 - Network Enumeration:** What two internal IPs were enumerated? **`10.1.0.154, 10.1.0.183`**

**Analysis:** The data indicates the attacker downloaded a packed executable named `scan.exe`, which subsequently extracted its contents (`advanced_ip_scanner.exe`) into a temporary directory. `DeviceProcessEvents` revealed that the tool was run in portable mode to minimize forensic artifacts on the disk. Following the scan, the threat actor enumerated network shares on specific hosts by executing `net.exe view \\<IP>` commands, targeting internal IP addresses `10.1.0.154` and `10.1.0.183` from the `as-srv` machine.

**Query Used (Scanner Tool Identification):**
```kusto
DeviceFileEvents
| where DeviceName == "as-pc2"
| where FileName contains "scan"
| where FileName endswith ".exe"
| project Timestamp, InitiatingProcessFileName, FileName, FolderPath
| sort by Timestamp asc
```
*<img width="800" alt="Q23" src="https://github.com/user-attachments/assets/b3f63dbf-4c88-4585-a065-11b99b7dd6c2" />*

**Query Used (Scanner Hash):**
```kusto
DeviceFileEvents
| where DeviceName == "as-pc2"
| where FileName in~ ("scan.exe", "advanced_ip_scanner.exe")
| project Timestamp, FileName, SHA256
| sort by Timestamp asc
```
*<img width="800" alt="Q24" src="https://github.com/user-attachments/assets/dac39242-e67f-4bd6-9375-c6f033606786" />*

**Query Used (Scanner Execution):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName =~ "scan.exe" or FileName contains "advanced"
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp asc
```
*<img width="800" alt="Q25" src="https://github.com/user-attachments/assets/eba943cc-33fb-4631-840f-243957d14977" />*

**Query Used (Network Enumeration):**
```kusto
union DeviceProcessEvents, DeviceEvents
| where Timestamp between(datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-29T00:00:00Z))
| where (ProcessCommandLine contains "\\\\10.") or (ActionType in~ ("NetworkShareConnected", "SmbSessionChanged"))
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, RemoteIP
```
*<img width="800" alt="Q26" src="https://github.com/user-attachments/assets/c6f8626b-b2e9-4263-9873-583e8097b457" />*

---

### SECTION 8: LATERAL MOVEMENT

**Cyber Range Investigation Flags:**
* **🚩 Q27 - Lateral Account:** What account was used to authenticate to AS-SRV? **`as.srv.administrator`**

**Analysis:** Analysis of `DeviceProcessEvents` on the compromised server (`as-srv`) confirms that the threat actor utilized the `as.srv.administrator` account to authenticate and execute subsequent reconnaissance commands, completing their lateral movement phase.

**Query Used:**
```kusto
union DeviceProcessEvents, DeviceEvents
| where DeviceName == "as-srv"
| where Timestamp between(datetime(2026-01-27T22:16:00Z) .. datetime(2026-01-27T22:19:00Z))
| where FileName =~ "net.exe"
| project Timestamp, AccountName, InitiatingProcessAccountName, ProcessCommandLine
```
*<img width="800" alt="Q27" src="https://github.com/user-attachments/assets/18720c88-ad1a-4b3f-9d17-da3d61f5b67d" />*

---

### SECTION 9: TOOL TRANSFER METHODS

**Cyber Range Investigation Flags:**
* **🚩 Q28 - Download Method:** What LOLBIN was first used to download tools? **`bitsadmin.exe`**
* **🚩 Q29 - Fallback Method:** What PowerShell cmdlet was used? **`Invoke-WebRequest`**

**Analysis:** The threat actor initially used the built-in utility `bitsadmin.exe` to download tools. They attempted to download `scan.exe` to multiple locations, indicating execution issues. Later, they successfully used bitsadmin to download `kill.bat`. After initial download attempts failed, the threat actor opened an interactive PowerShell session and utilized the `Invoke-WebRequest` cmdlet as a fallback method to successfully download `scan.exe`.

**Query Used (Bitsadmin):**
```kusto
DeviceProcessEvents
| where DeviceName in~ ("as-pc2", "as-srv")
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc
```
*<img width="800" alt="Q28" src="https://github.com/user-attachments/assets/8b920e5c-0740-4e35-9316-7ef92d716178" />*

**Query Used (PowerShell Fallback):**
```kusto
DeviceEvents
| where Timestamp between(datetime(2026-01-27T18:00:00Z) .. datetime(2026-01-28T05:00:00Z))
| where DeviceName in~ ("as-pc2", "as-srv")
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("http", "ftp", "Invoke", "wget", "curl", "WebClient", "download")
| project Timestamp, DeviceName, AdditionalFields
```
*<img width="800" alt="Q29" src="https://github.com/user-attachments/assets/f185098a-16c4-4d79-af5c-f03e655d8c67" />*

---

### SECTION 10: DATA EXFILTRATION

**Cyber Range Investigation Flags:**
* **🚩 Q30 - Staging Tool:** What staging tool compressed the data? **`st.exe`**
* **🚩 Q31 - Staging Hash:** What is the SHA256 of the staging tool? **`512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`**
* **🚩 Q32 - Exfil Archive:** What archive was created? **`exfil_data.zip`**

**Analysis:** During the investigation into potential data exfiltration, an analysis of `DeviceFileEvents` was conducted to identify the creation of the staging archive `exfil_data.zip`. The logs revealed that on January 27, 2026, at 22:24:09 UTC, the executable `st.exe` was responsible for creating this compressed archive on the host `as-srv` in the `C:\Users\Public\` directory prior to exfiltration.

**Query Used (Archive Creation):**
```kusto
DeviceFileEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where FileName == "exfil_data.zip"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```
*<img width="800" alt="Q30" src="https://github.com/user-attachments/assets/104f391f-b0f4-4c52-aeae-c1fd1684fd1d" />*

**Query Used (Staging Tool Hash):**
```kusto
DeviceProcessEvents
| where FileName =~ "st.exe"
| project TimeGenerated, DeviceName, FileName, SHA256
```
*<img width="800" alt="Q31" src="https://github.com/user-attachments/assets/6c7a4e1f-a980-42e8-88bb-f6b9b23707cb" />*

**Query Used (Exfil Archive Path):**
```kusto
DeviceFileEvents
| where DeviceName == "as-srv"
| where InitiatingProcessFileName =~ "st.exe"
| project TimeGenerated, ActionType, FileName, FolderPath
```
*<img width="800" alt="Q32" src="https://github.com/user-attachments/assets/bf5f4426-53c1-48d2-9f8b-2e6b19ddbb2c" />*

---

### SECTION 11: RANSOMWARE DEPLOYMENT

**Cyber Range Investigation Flags:**
* **🚩 Q33 - Ransomware Filename:** What is the ransomware filename? **`updater.exe`**
* **🚩 Q34 - Ransomware Hash:** What is the SHA256 of the ransomware? **`e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`**
* **🚩 Q35 - Ransomware Staging:** What process staged the ransomware on AS-SRV? **`powershell.exe`**
* **🚩 Q36 - Recovery Prevention:** What command was used? **`vssadmin delete shadows /all /quiet`**
* **🚩 Q37 - Ransom Note Origin:** What process dropped the ransom note? **`updater.exe`**
* **🚩 Q38 - Encryption Start:** What time was the ransom note dropped? **`22:18:33`**
* **🚩 Q39 - Cleanup Script:** What script deleted the ransomware? **`clean.bat`**

**Analysis:** The ransomware executable was staged by `powershell.exe` and disguised as a legitimate background process named `updater.exe`. A review of the execution timestamps against the creation of the ransom notes (22:18:33 UTC) identified the malicious payload hash. Prior to the encryption phase, the threat actor initiated a sequence of commands on `as-pc2` using `wsync.exe` to prevent system recovery, primarily using `vssadmin delete shadows /all /quiet`. Following the encryption, the process `cmd.exe` executed a script named `clean.bat` in the `C:\ProgramData\` directory to delete the malicious executables and hinder forensic analysis.

**Query Used (Ransomware Identification):**
```kusto
DeviceFileEvents
| where DeviceName == "as-srv" 
| where ActionType == "FileCreated" 
| where FileName == "akira_readme.txt" 
| project TimeGenerated, ActionType, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc
```
*<img width="800" alt="Q33" src="https://github.com/user-attachments/assets/1786dafb-654d-4576-90cb-012ecbed1561" />*

**Query Used (Ransomware Hash):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-srv"
| where FileName =~ "updater.exe"
| where FolderPath contains "ProgramData"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
```
*<img width="800" alt="Q34" src="https://github.com/user-attachments/assets/d01209fb-c712-4b7e-8008-cad3a6c0fbb8" />*

**Query Used (Ransomware Staging):**
```kusto
DeviceFileEvents
| where DeviceName == "as-srv"
| where ActionType == "FileCreated"
| where FileName =~ "updater.exe"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
```
*<img width="800" alt="Q35" src="https://github.com/user-attachments/assets/bbbc24d9-25bb-4c06-be78-f281c2fdae89" />*

**Query Used (Recovery Prevention):**
```kusto
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName == "wsync.exe"
| where ProcessCommandLine has_any ("vssadmin", "wmic", "bcdedit")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
*<img width="800" alt="Q36" src="https://github.com/user-attachments/assets/19c0af9d-cbb8-4e22-b7ef-bfa071f919e3" />*

**Query Used (Ransom Note Creation):**
```kusto
DeviceFileEvents
| where FileName =~ "akira_readme.txt"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FolderPath
| sort by TimeGenerated asc
| take 1
```
*<img width="800" alt="Q37" src="https://github.com/user-attachments/assets/c3dd888f-6222-4ef3-a458-784ac6a55b80" />*

**Query Used (Ransom Note Timestamp):**
```kusto
DeviceFileEvents
| where FileName =~ "akira_readme.txt"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FolderPath
| sort by TimeGenerated asc
| take 1
```
*<img width="982" height="288" alt="Q38" src="https://github.com/user-attachments/assets/571335f1-70f6-4d70-9ef6-11b65782be56" />*

**Query Used (Cleanup Script):**
```kusto
DeviceFileEvents
| where FileName in~ ("updater.exe", "wsync.exe")
| where ActionType == "FileDeleted"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```
*<img width="800" alt="Q39" src="https://github.com/user-attachments/assets/d2755641-dc6f-4174-83f5-1e566403b79f" />*

---

### SECTION 12: FINAL INCIDENT SCOPE

**Cyber Range Investigation Flags:**
* **🚩 Q40 - Affected Hosts:** What hosts were compromised? **`as-pc2, as-srv`**

**Analysis:** Based on a comprehensive review of the environment using the specific malicious SHA256 hashes identified during the investigation, the scope of the compromise was strictly limited to two hosts: `as-pc2` (initial access and staging) and `as-srv` (lateral movement and primary encryption target).

**Query Used (Verified Scope Definition):**
```kusto
union DeviceProcessEvents, DeviceFileEvents
| where SHA256 in~ (
    "e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b", // Malicious updater.exe
    "0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654", // Malicious wsync.exe (Replacement)
    "66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b"  // Malicious wsync.exe (Original)
) or FileName == "akira_readme.txt"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by DeviceName
| sort by FirstSeen asc
```
*<img width="800" alt="Q40" src="https://github.com/user-attachments/assets/cd42a9dd-d3eb-43ca-b621-5dd6795232f3" />*

---

## 7. Conclusion
The investigation successfully identified the root cause, the attack path, and the full scope of the Akira ransomware incident. By tracking the threat actor from their initial entry through AnyDesk to the final deployment of the ransomware, the incident response team was able to isolate the two compromised hosts (`as-pc2` and `as-srv`). 

Ashford Sterling Recruitment can now use the provided Indicators of Compromise (IoCs) to block further connections to the attacker's infrastructure. With the network scoped and contained, the business can safely begin the recovery process. Implementing the strategic recommendations outlined in this report will greatly harden the environment and secure the network against future threats.
