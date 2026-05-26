# SENTINEL-DETECTION-RULES
# 🔍 Microsoft Sentinel Detection Rules

A collection of custom KQL (Kusto Query Language) analytics rules, hunting queries, and workbook templates for Microsoft Sentinel — focused on detecting common attack techniques mapped to the MITRE ATT&CK framework.

Built from hands-on experience working with Microsoft Sentinel in a SOC environment.

---

## 📂 Repository Structure

```
sentinel-detection-rules/
├── analytics-rules/         ← Scheduled detection rules (alert triggers)
│   ├── identity/            ← Account & authentication threats
│   ├── endpoint/            ← Endpoint & process-based threats
│   ├── network/             ← Network anomalies & C2 detection
│   └── cloud/               ← Azure & cloud resource threats
├── hunting-queries/         ← Proactive threat hunting KQL
├── workbooks/               ← Dashboard & reporting templates
└── README.md
```

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access (TA0001) | T1566 Phishing, T1078 Valid Accounts |
| Credential Access (TA0006) | T1110 Brute Force, T1110.003 Password Spray |
| Defence Evasion (TA0005) | T1036 Masquerading, T1562 Impair Defences |
| Lateral Movement (TA0008) | T1021 Remote Services, T1550 Pass the Hash |
| Exfiltration (TA0010) | T1048 Exfiltration Over Alternative Protocol |
| Persistence (TA0003) | T1547 Boot Autostart, T1053 Scheduled Task |

---

## 🧰 Requirements

- Microsoft Sentinel workspace
- Log Analytics workspace with the following tables enabled:
  - `SigninLogs` — Azure AD sign-in logs
  - `SecurityEvent` — Windows Security Event logs
  - `OfficeActivity` — Microsoft 365 activity logs
  - `AzureActivity` — Azure resource activity logs
  - `CommonSecurityLog` — Firewall / network device logs

---

## 📋 How to Deploy a Rule

1. Open **Microsoft Sentinel** → Analytics → Create → Scheduled query rule
2. Copy the KQL from any file in `analytics-rules/`
3. Set the **query schedule** and **alert threshold** as noted in each file
4. Map the **MITRE ATT&CK** tactics and techniques
5. Configure **alert grouping** and **automated response** as needed

---

## 👤 Author

**Sai Teja Adapa** — SOC Analyst Level 1  
[LinkedIn](https://www.linkedin.com/in/tejaadapa23) | [Email](mailto:tejadapa2309@gmail.com)

> All queries are written for educational and defensive security purposes. Tested against Microsoft Sentinel in a SOC environment. Adapt thresholds and table names to match your environment before deploying.
