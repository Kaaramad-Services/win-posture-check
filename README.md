# Windows Security Posture Check (Read-Only)

This tool generates a **real, evidence-based security posture report** for **Windows 10 and Windows 11**.

## 🔒 Safety

* **Read-only**: does NOT change registry, services, firewall, BitLocker, or updates
* Uses only built-in Windows queries
* Outputs **JSON + HTML report**
* Includes **SHA256 integrity hashes**

## 📊 Features

* 0–100 weighted security score
* CIS-style baseline checks
* Browser security checks (Edge + Chrome)
* Defender, Firewall, BitLocker, RDP, TLS, LSA, SMBv1, Updates, Services

## ▶️ How to run

```powershell
git clone https://github.com/Kaaramad-Services/win-posture-check.git
cd win-posture-check
powershell -ExecutionPolicy Bypass -File .\WinPostureCheck.ps1 -OutDir .\report -OpenHtml
```

Run as **Administrator** for full results.

## 🔍 Verify file integrity (recommended)

```powershell
Get-FileHash .\WinPostureCheck.ps1 -Algorithm SHA256
```

## ⚠️ Disclaimer

This project is for **security assessment and education only**.
It performs **local read-only checks** and does not scan networks or exploit systems.
