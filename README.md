# 🔍 NetProbe - Network Reconnaissance Tool

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red)
![License](https://img.shields.io/badge/License-MIT-green)

> A powerful network reconnaissance tool built in Python for security researchers and penetration testers.

---

## ⚡ Features

- **Port Scanner** — Multi-threaded port scanning with open/closed status
- **DNS Lookup** — Fetches A, MX, and NS records
- **HTTP Headers** — Extracts key security-related headers
- **SSL Certificate** — Retrieves certificate details including Public Key, issuer, and expiry dates
- **Input Validation** — Validates domain format and existence before scanning

---

## 🛠️ Requirements

```bash
pip install dnspython requests beautifulsoup4 colorama cryptography lxml
```

---

## 🚀 Usage

```bash
python3 netprobe.py
```

Then follow the prompts:

```
Enter Domain To Scan : example.com
Enter Ports To Scan (Comma Separated): 80,443,22,8080
```

---

## 📸 Output Example

```
================Network Recon=================
 | Port Scanning :
    -Port 80 Open
    -Port 443 Open
    -Port 22 Closed
 | Dns LookUp :
    -A Record
      * Ip      : 93.184.216.34
    -MX Record
      * Server  : mail.example.com.
    -NS Record
      * Server  : ns1.example.com.
 | HTTP Headers :
      * Website Title : Example Domain
      * Server        : ECS
      * Content-Type  : text/html
 | SSL Certificates :
      * Subject  : example.com
      * Issuer   : DigiCert
      * notAfter : Apr 20 00:00:00 2025 GMT
```

---

## 📚 Libraries Used

| Library | Purpose |
|---|---|
| `socket` | Port scanning & SSL connection |
| `threading` | Multi-threaded port scanning |
| `dns.resolver` | DNS record lookup |
| `requests` | HTTP headers fetching |
| `ssl` | SSL certificate retrieval |
| `cryptography` | Public key extraction |
| `colorama` | Colored terminal output |
| `re` | Input validation |

---

## ⚠️ Disclaimer

> This tool is intended for **educational purposes** and **authorized penetration testing only**.
> Do not use against systems you don't have permission to test.

---

## 👤 Author

**v4nixx** — [@v4nixxpy](https://github.com/v4nixxpy)
