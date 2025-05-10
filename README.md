# Email-Forensic-Analyzer

This Email Forensic Analyzer is a python-based tool designed to dissect email messages(.em,.msg) for security analysis, threat intelligence, and forensic investigation.  It provides deep insights into:

**Email Authentication (SPF, DKIM, DMARC)**

**Header Anomalies & Spoofing Indicators**

**URL & Attachment Threat Analysis**

**IP Reputation & Geolocation**

**Macro & Malicious Content Detection**

This tool is valuable for:

**Red Teams (simulating phishing attacks, testing defenses)**

**Blue Teams (incident response, email security monitoring)**

**Digital Forensics (investigating breaches, analyzing malicious emails)**

## 1. Email Authentication Checks

SPF	--          Validates sender IP against SPF records (Pass/Fail/Softfail)

DKIM	--        Verifies cryptographic signature integrity (Body/Header Tampering)

DMARC	--        Parses DMARC policies (Reject/Quarantine/None)

ARC/BIMI --	    Checks additional authentication headers

## 2. Header & Metadata Analysis
IP Extraction (From Received, X-Originating-IP)

Geolocation (MaxMind GeoLite2 + IPinfo.io fallback)

Header Anomalies (Mismatched From/Return-Path, missing Message-ID)

Suspicious Headers (X-Mailer, X-Priority)

## 3. URL & Link Analysis
Extracts URLs from HTML, Plaintext, Headers

Detects:

Shortened URLs (bit.ly, goo.gl)

IP-Based URLs 

High-Risk TLDs (.ru, .cn, .top)

Phishing Keywords ("login," "verify," "account")

## 4. Attachment & Macro Analysis
File Type Detection (Magic Numbers, Extensions)

SHA-256 Hashing (For VirusTotal Lookups)

Macro Scanning (VBA Code Analysis via oletools)

Suspicious Extensions (.exe, .js, .vbs, .docm)

## 5. Threat Intelligence Integration
VirusTotal API (IP/Domain Reputation)

IPQualityScore API (Proxy/VPN/TOR Detection)

Local Threat Lists (Customizable Blocklists)

## Red Team Use Cases
**1. Phishing Simulation Testing**

Test SPF/DKIM/DMARC bypass techniques

Identify legitimate-looking header spoofing

Analyze URL redirection effectiveness

**2. Payload Delivery Analysis**

Check if malicious attachments evade detection

Test macro-enabled document behavior

Evaluate sandbox evasion techniques

**3. Open-Source Intelligence (OSINT)**

Map sending infrastructure (IPs, ASNs)

Identify geographic patterns in attack campaigns

## Blue Team Use Cases
**1. Incident Response (IR)**

Triage malicious emails (Post-breach analysis)

Extract IOCs (IPs, URLs, Attachments)

Validate email authenticity (SPF/DKIM failures)

**2. Threat Hunting**

Detect anomalous sender patterns

Hunt for hidden malicious links

Identify credential phishing attempts

**3. Security Awareness Training**

Generate real-world phishing examples

Show how attackers bypass filters

## Digital Forensics Use Cases
**1. Email Artifact Analysis**

Reconstruct email delivery path (Received headers)

Identify forged headers (Spoofing detection)

**2. Malware Analysis**

Extract malicious macros from Office docs

Analyze embedded exploit links

**3. Legal & Compliance**

Prove email tampering (DKIM failures)

Track sender infrastructure (IP geolocation)

**required libraries:**
```
dkimpy, dnspython, geoip2, python-magic, requests, oletools, colorama, beautifulsoup4
```
**GeoLite2 Database Setup**
```
1. Download GeoLite2-City.mmdb from MaxMind
2. Place it in the script's working directory
```

## API Keys

Set environment variables:
```
export VIRUSTOTAL_API_KEY="your_key"
export IPQS_API_KEY="your_key"
```
## Usage
```
python email_analyzer.py <insert_your_phishing.eml_file_here>
```
**JSON Output for automation**
```
python email_analyzer.py <insert_your_phishing.eml_file_here> --json
```
