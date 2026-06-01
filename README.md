# Windows Security Assessment Report Generator

A PowerShell-based Windows Security Assessment tool that collects system security information, performs a basic risk assessment, generates a modern HTML dashboard, and automatically exports the report to PDF using Microsoft Edge or Google Chrome in headless mode.

## Features

### Security Assessment

* Collects Windows system information
* Enumerates local users and administrator accounts
* Checks Microsoft Defender status
* Lists listening TCP ports
* Captures established network connections
* Audits running services
* Audits startup programs
* Audits scheduled tasks
* Enumerates shared folders
* Generates security recommendations

### Reporting

* Modern HTML dashboard
* Executive security summary
* Security score calculation
* Risk level classification (Low / Medium / High)
* PDF report generation
* Evidence collection for audit purposes

### Evidence Collection

The script stores raw output from collected commands for further investigation:

* Users
* Administrators
* Services
* Startup Programs
* Scheduled Tasks
* Listening Ports
* Established Connections
* Network Shares

---

## Requirements

### Operating System

* Windows 10
* Windows 11
* Windows Server 2019+
* Windows Server 2022+

### PowerShell

* PowerShell 5.1 or later

### Browser

One of the following must be installed:

* Microsoft Edge
* Google Chrome

The browser is used for PDF generation via headless mode.

---

## Installation

Clone the repository:

```powershell
git clone https://github.com/<your-username>/windows-security-assessment.git
cd windows-security-assessment
```

---

## Usage

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\WindowsSecurityAssessment.ps1
```

Specify a custom output directory:

```powershell
.\WindowsSecurityAssessment.ps1 -OutputDir C:\Assessment
```

---

## Generated Output

```text
Assessment
│
├── SecurityAssessment.html
├── SecurityAssessment.pdf
│
└── Evidence
    ├── users.txt
    ├── administrators.txt
    ├── services.txt
    ├── startup.txt
    ├── scheduled_tasks.txt
    ├── listening_ports.txt
    ├── established_connections.txt
    └── shares.txt
```

---

## Security Score Logic

The script assigns a score out of 100 based on selected security checks.

Current scoring factors include:

| Check                                  | Impact |
| -------------------------------------- | ------ |
| Defender Real-Time Protection Disabled | -30    |
| MySQL Exposed on Network               | -4     |
| PostgreSQL Exposed on Network          | -4     |
| Excessive Administrator Accounts       | -10    |

### Risk Levels

| Score    | Risk Level |
| -------- | ---------- |
| 90 - 100 | Low        |
| 70 - 89  | Medium     |
| Below 70 | High       |

---

## Example Findings

### Passed

* Microsoft Defender Enabled
* Real-Time Protection Enabled
* No Unknown Administrator Accounts
* No Suspicious Startup Entries

### Warnings

* MySQL listening on 0.0.0.0:3306
* PostgreSQL listening on 0.0.0.0:5432

### Recommendations

* Restrict database services to localhost where possible
* Perform regular full antivirus scans
* Review exposed network services periodically

---

## Example Screenshot

The report contains:

* Executive Dashboard
* Security Score
* Risk Assessment
* System Information
* Defender Status
* Listening Ports
* Network Connections
* Running Services
* Startup Applications
* Scheduled Tasks
* Recommendations

---

## Limitations

This tool is intended for:

* Internal security reviews
* System health checks
* Basic workstation assessments
* Security awareness reporting

This tool is **not** a replacement for:

* Vulnerability scanners
* Endpoint Detection and Response (EDR)
* Penetration testing
* Security Information and Event Management (SIEM)

---

## Roadmap

Future enhancements:

* Firewall analysis
* Installed software inventory
* Suspicious process detection
* Browser extension auditing
* CVE lookup integration
* Windows event log analysis
* Interactive charts
* Compliance reporting
* Multi-host assessment support

---

## Disclaimer

This tool is provided for educational, administrative, and defensive security purposes only.

Always review findings manually before making security decisions in production environments.

---

## License

MIT License
