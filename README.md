# Tesla Reconnaissance & Penetration Testing

## Overview

This project documents a security reconnaissance and penetration testing assessment performed against **Tesla, Inc.**

The objective of the assessment was to identify publicly exposed information, map the external attack surface, enumerate DNS records and subdomains, fingerprint web infrastructure, and identify security technologies protecting the target.

> **Disclaimer:** This project was conducted for educational purposes and within an authorized testing environment/scope. No unauthorized access or destructive activity was performed.

---

## Objectives

The main objectives of this assessment were:

* Perform company profiling and passive reconnaissance
* Enumerate subdomains
* Perform DNS enumeration
* Identify web technologies and edge infrastructure
* Detect Web Application Firewall (WAF) technologies
* Analyze HTTP/TLS responses
* Review publicly available GitHub information
* Document findings and security observations

---

## Methodology

The assessment followed a reconnaissance-focused penetration testing workflow:

```text
Company Profiling
       ↓
Subdomain Enumeration
       ↓
DNS Enumeration
       ↓
Web Fingerprinting
       ↓
WAF Detection
       ↓
GitHub Enumeration
       ↓
Analysis & Reporting
```

---

## Tools Used

| Tool           | Purpose                         |
| -------------- | ------------------------------- |
| Google Dorking | Passive information gathering   |
| Amass          | Subdomain enumeration           |
| Subfinder      | Passive subdomain enumeration   |
| grep           | Result analysis and filtering   |
| dig            | DNS enumeration                 |
| WhatWeb        | Web technology fingerprinting   |
| curl           | HTTP, TLS and response analysis |
| wafw00f        | WAF detection                   |
| WHOIS          | Domain registration enumeration |
| GitHub         | Public-source reconnaissance    |

---

## Key Findings

### Subdomain Enumeration

Several subdomains were identified during passive enumeration. Frequently observed results included:

```text
shop.tesla.com
link.tesla.com
```

### DNS Enumeration

The assessment identified:

* Multiple IPv4 addresses for `tesla.com`
* No AAAA record returned
* Microsoft Exchange Online Protection as the MX provider
* Multiple TXT records containing SPF and third-party service verification records
* DMARC policy configured with `p=reject`
* Akamai and UltraDNS DNS infrastructure

### Web Fingerprinting

The target was observed behind **Akamai edge infrastructure**.

Observed indicators included:

```text
AkamaiGHost
X-AK-Cache
```

### WAF Detection

`wafw00f` identified:

```text
Kona SiteDefender (Akamai)
```

### HTTP Response

The target returned:

```text
HTTP/1.1 403 Forbidden
```

The origin server IP and underlying origin technology were not identified during the performed reconnaissance.

### GitHub Enumeration

The public Tesla GitHub organization was reviewed. No directly actionable security-sensitive information was identified during the performed review.

---

## Detailed Report

The complete methodology, evidence, observations, and assessment are documented in:

**[Final Report](https://github.com/SilentSpectre-arch/OSINT-Info-Gathring-Tesla/blob/main/Final-Report.md)**

---

## Disclaimer

This repository is intended for **educational and security research purposes**. The information presented here documents reconnaissance techniques and security assessment methodology. Testing should only be performed against systems for which explicit authorization has been obtained.
