# 🛡️ Akira Ransomware Incident Response Investigation

## 📌 Overview

This project analyzes a targeted ransomware attack against Ashford Sterling Recruitment.

The attacker gained access through an exposed remote access tool, disabled security controls, moved laterally across the network, exfiltrated sensitive data, and deployed Akira ransomware to encrypt critical systems.

---

## 🎯 Key Skills Demonstrated

- Threat Hunting (KQL)
- Incident Response
- Log Correlation
- MITRE ATT&CK Mapping
- Endpoint & Network Analysis

---

## 🚨 Executive Summary

On January 27, 2026, Ashford Sterling Recruitment experienced a ransomware attack attributed to the **Akira** threat group.

The attacker:
- Gained access using a pre-installed remote access tool (AnyDesk)
- Disabled Microsoft Defender protections
- Stole administrative credentials
- Moved laterally to a file server
- Exfiltrated sensitive data
- Deployed ransomware and encrypted systems

The attack was contained to two hosts but represents a critical compromise of internal infrastructure.

---

## 🔓 Initial Access

The attacker gained access using a pre-installed remote access tool (AnyDesk), executed under a compromised user account.

*<img width="800" alt="Q15" src="https://github.com/user-attachments/assets/b7c58ba4-a3c3-4483-9bd8-08eac1ef1d2e" />*

---

## 🌍 Attacker Infrastructure

External connections to an untrusted public IP confirmed active attacker-controlled access.

*<img width="800" alt="Q17" src="https://github.com/user-attachments/assets/8a9d3c39-605b-4153-a091-69c7059c7e59" />*

---

## 🛑 Defense Evasion

Microsoft Defender protections were disabled via registry modification, allowing the attacker to operate without detection.

*<img width="800" alt="Q9" src="https://github.com/user-attachments/assets/bd93a42d-356d-432d-8e3c-fef9607e1420" />*

---

## 🔑 Credential Access

The attacker targeted the LSASS process to extract administrator credentials.

*<img width="800" alt="Q14" src="https://github.com/user-attachments/assets/06d81708-4e3e-42c3-816e-e535d26aa0db" />*

---

## 🌐 Command & Control (C2)

A malicious beacon (`wsync.exe`) was deployed to maintain communication with attacker infrastructure.

*<img width="800" alt="Q19" src="https://github.com/user-attachments/assets/f01bdbed-ca8e-4649-8e3d-5d66536a074e" />*

---

## 📤 Data Exfiltration

Sensitive data was compressed into an archive prior to exfiltration.

*<img width="800" alt="Q30" src="https://github.com/user-attachments/assets/104f391f-b0f4-4c52-aeae-c1fd1684fd1d" />*

---

## 💥 Ransomware Execution

The ransomware payload was deployed, encrypting files and dropping a ransom note.

*<img width="800" alt="Q33" src="https://github.com/user-attachments/assets/1786dafb-654d-4576-90cb-012ecbed1561" />*

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|-------|----------|-------------|
| Initial Access | T1133 – External Remote Services | AnyDesk used for unauthorized access |
| Defense Evasion | T1562.001 – Impair Defenses | Defender disabled via registry |
| Credential Access | T1003.001 – LSASS Dumping | Credentials extracted from memory |
| Discovery | T1046 – Network Service Discovery | Internal scanning performed |
| Lateral Movement | T1021.002 – SMB | Movement to file server |
| Collection | T1560.001 – Archive Collected Data | Data compressed before exfiltration |
| Impact | T1486 – Data Encrypted for Impact | Ransomware encrypted files |

---

## 📌 Indicators of Compromise (IOCs)

**IP Addresses:**
- 88.97.164.155  
- 172.67.174.46  
- 104.21.30.237  

**Domains:**
- sync.cloud-endpoint.net  
- cdn.cloud-endpoint.net  

**Files:**
- wsync.exe  
- updater.exe  
- kill.bat  
- exfil_data.zip  

---

## 🔒 Recommendations

- Restrict unauthorized remote access tools (AnyDesk)
- Enforce least privilege access controls
- Enable Defender tamper protection
- Deploy Credential Guard
- Implement network segmentation
- Maintain offline, immutable backups

---

## 🧠 Analyst Insight

This attack demonstrates how legitimate remote access tools can be abused to bypass traditional perimeter defenses.

Once access was established, the attacker quickly disabled endpoint protections and escalated privileges, enabling full control of the environment.

This case highlights the importance of controlling remote access tools, enforcing strong endpoint protections, and limiting credential exposure to prevent complete domain compromise.

---

## 📎 Conclusion

This investigation successfully traced the attacker from initial access through ransomware deployment.

By identifying attacker behavior and infrastructure, the scope of the compromise was contained and critical weaknesses in the environment were exposed.

---

## 👤 Author

Jason Stokes  
Cybersecurity | Threat Hunting | Incident Response
