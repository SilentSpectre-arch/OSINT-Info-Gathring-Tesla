## 1. Subdomain Enumeration

### Methodology

Google Dorking, Amass, Subfinder and grep were used...

### Findings

| Subdomain | Occurences |
|---|---:|
| shop.tesla.com | 3 |
| link.tesla.com | 3 |
| xmail.tesla.com| 2 |
| wire.tesla.com | 2 |
| warehouse.tesla.com | 2 |
| vpn2.tesla.com | 2 |
| vpn1.tesla.com | 1 |

## 2. Company Profiling

### 2.1 Company Overview

Tesla, Inc is an American company operating primarily in the automotive, energy storage, and solar power industries. The company developers and manufactures electric vehicles, energy storage systems, and solar energy products.

### Company Info

| Attributes | Info |
| --- | ---: |
| Company Name | Tesla,Inc. |
| Former Name | Tesla Motors,Inc.(2003-2017) |
| Founded | 2003|
| Industry | Automotive,Energy Storage,Solar Power |
| Stock Symbol | NASDAQ:TSLA |
| Market Indexes | Nasdaq-100, S&P 100, S&P 500 |
| CEO | Elon Musk |
| Chair | Robyn Denholm |
| Official Website | tesla.com |

### 2.2 Headquarters

Tesla's headquarters is located at Gigafactory Texas in Austin, Texas.

Headquarters:

Tesla, Inc.
1 Tesla Road
Austin, TX 78725
United States

Tesla also maintains an engineering headquarters in Palo Alto, California:

1501 Page Mill Road
Palo Alto, CA
United States

### 2.3 Company History

Tesla was founded in 2003 by Martin Eberhard and Marc Tarpenning. The company was originally established under the name Tesla Motors, Inc. and later changed its name to Tesla, Inc. in 2017.

The company has expanded from its initial focus on electric vehicles into additional areas including energy storage and solar power.

## 3. DNS Enumeration

### 3.1 A Record Enumeration

````bash
dig tesla.com A
````

#### Findings

The domain `tesla.com` resolved to multiple IPv3 addresses

| IPv4 Addresses |
| --- |
2.18.49.207
2.18.54.207
2.18.50.207
2.18.52.207
23.40.100.207
23.7.244.207
2.18.51.207
2.18.55.207
2.18.53.207
2.18.48.207

- TTL: 244 seconds

#### Observation

The presence of multiple A records suggests the use of Load balancing, Contenet Delivery Network (CDN) infrastructure , or geographically distributed hosting.

### AAAA Record Enumeration

````bash
dig tesla.com AAAA
````

#### Findings

No AAAA records were returned for `tesla.com`

| Value | Field |
| --- | ---: |
| None | IPv6 Address |
| edns69.ultradns.com | SOA Server |
| domain.teslamotors.com | Responsible Mailbox |

#### Observation

No publicly accessible IPv6 address was returned for the queried domain.

### 3.3 MX Record Enumeration

````bash
dig tesla.com MX
````

#### Findings

The domain has a single mail exchanger.

| Value | Field |
| --- | ---: |
| 10 | Priority |
| tesla-com.mail.protection.outlook.com | Mail Server |
| Microsoft Outlook / Exchange Online Protection | Email Platform |
| TTL | 300 seconds |

#### Observation 

The MX configuration indicates that Tesla uses Microsoft Exchange Online Protection(EOP) as its public email gateway.

### 3.4 TXT Record Enumeration

````bash
dig @1.1.1.1 tesla.com TXT
````

#### Findings

A total of 35 TXT records were identified

#### Key Findings

- SPF Policy present
- Microsoft 365 verification records
- Google domain verification
- Apple domain verification
- Bugcrowd verification
- Atlassian verification
- Cloudflare Dashboard SSO verification
- Additional verification records for Docker, Jamf, TeamViewer, OneTrust, Zapier, LogMeIn, Adobe, Dell Technologies, and Cursor

#### SPF Observation

The SPF policy authorizes multiple third-party services, including:
- Microsoft 365
- SendGrid
- Zendesk
- Qualtrics
- KnowBe4
- SendCloud

#### Observation

The TXT records reveal extensive integration with cloud and enterprise services. These records are expected for a large organization but provide valuable context for attack surface mapping during reconnaissance.

### 3.5 DMARC Enumeration

````bash
dig @1.1.1.1 _damrc.tesla.com TXT
````

#### Findings

| Field | Value |
| --- | ---: |
| Version | DMARC1 |
| Policy | p=reject |
| Percentage | 100% |
| Aggregates Reports | ag.dmarcian.com |
| Forensic Reports | fr.dmarcian.com |
| Failure Option | fo=1 |

#### Observation

Tesla enforces a strict DMARC policy by rejecting unauthenticated emails and applying the policy to 100% of messages. DMARC reporting is configured through Dmarcian,indicating active monitoring of email authentication.


### 3.6 CNAME Enumeration

````bash
dig tesla.com CNAME
````

#### Findings
No CNAME record exist for the apex domain.

| Field | Value |
| --- | ---: |
| CNAME | None |
| Primary DNS | edns69.ultradns.com |
| Responsible Mailbox | domain.teslamotors.com |

#### Observation

The root domain resolves directly through A record rather than refrencing another hostname via CNAME.

### DNS Enumeration Summary

| Record Type | Result |
| --- | ---: |
| A | Multiple IPv4 addresses |
| AAAA | No IPv6 record |
| MX | Microsoft Exchange Online Protection |
| TXT | 35 records including SPF and service verifications |
| DMARC | p=reject, pct=100 |
| CNAME | None |

# 4. Web Fingerprinting & WAF Detection

## Objective

The objective of this phase was to identify the web server, CDN/edge infrastructure, HTTP response behavior, TLS configuration, security headers, and Web Application Firewall (WAF) protecting the target domain.

**Target:** `tesla.com`

**Date:** 2026-08-20

**Tools Used:**

* WhatWeb
* curl
* wafw00f

---

## 4.1 WhatWeb

**Tool:** WhatWeb

### Findings

**Web Server / CDN**

* Akamai infrastructure was detected.
* `HTTPServer: AkamaiGHost`

**HTTP Response**

* `http://tesla.com` returned HTTP `403 Forbidden`.
* Page title: `Access Denied`

**Observed IP**

* `2.18.48.207`

### Assessment

The results indicate that the target is served through **Akamai edge/CDN infrastructure**, which may provide an additional security and WAF layer between external clients and the origin server.

The observed `403 Forbidden` response indicates that access was denied by the edge infrastructure. This response alone does not indicate a vulnerability.

### Evidence

![WhatWeb Results](screenshots/whatweb.png)

---

## 4.2 HTTP Header Analysis with curl

**Tool:** `curl -I`

### HTTP Response

* Status Code: `403 Forbidden`
* Response indicates an `Access Denied` condition.

### CDN / Edge Infrastructure

The following headers were observed:

* `Server: AkamaiGHost`
* `X-AK-Cache: Error from child`

### Akamai Error Identification

An `X-Reference-Error` header was observed, indicating that the returned error/reference response was generated by Akamai infrastructure.

### Assessment

The response confirms that the target is operating behind Akamai edge infrastructure. The origin server technology could not be identified from the returned HTTP response.

### Evidence

![curl HTTP Headers](screenshots/curl-headers.png)

---

## 4.3 Detailed Connection Analysis with curl

**Tool:** `curl -v tesla.com`

### DNS / Infrastructure

Multiple IPv4 addresses were returned:

```text
2.18.53.207
23.7.244.207
23.40.100.207
2.18.52.207
2.18.48.207
2.18.51.207
2.18.50.207
2.18.49.207
2.18.54.207
2.18.55.207
```

The results are consistent with the use of distributed CDN/edge infrastructure.

The origin server IP address was not identified during this test.

### CDN / Edge

The following indicators were observed:

* `AkamaiGHost`
* `X-AK-Cache`
* Akamai EdgeSuite error URL

These indicators further support the presence of Akamai edge infrastructure.

---

### TLS Configuration

The TLS connection negotiated the following parameters:

| Parameter     | Value                    |
| ------------- | ------------------------ |
| TLS Version   | TLS 1.3                  |
| Cipher        | `TLS_AES_256_GCM_SHA384` |
| Key Exchange  | `X25519MLKEM768`         |
| HTTP Protocol | HTTP/1.1                 |

### TLS Certificate

| Parameter                      | Value               |
| ------------------------------ | ------------------- |
| Common Name (CN)               | `tesla.com`         |
| Subject Alternative Name (SAN) | `tesla.com`         |
| Issuer                         | Let's Encrypt (YR2) |
| Public Key                     | RSA 2048            |
| Signature Algorithm            | SHA256 with RSA     |
| Verification                   | Successful          |
| Valid From                     | 2026-08-16          |
| Valid Until                    | 2026-11-14          |

### HTTP Response

| Parameter      | Value           |
| -------------- | --------------- |
| Status         | `403 Forbidden` |
| Server         | `AkamaiGHost`   |
| Content-Type   | `text/html`     |
| Content-Length | 359 bytes       |

An Access Denied response was returned by the target.

### Security Headers

The following security-related headers were observed:

```text
Strict-Transport-Security: max-age=15768000
Permissions-Policy: interest-cohort=()
```

### Assessment

The target is protected by Akamai edge infrastructure. The origin server technology and origin IP address were not identified during this assessment.

The `403 Forbidden` response should not be interpreted as a vulnerability by itself. Instead, it demonstrates that the edge infrastructure is actively controlling or restricting the received request.


---

## 4.4 WAF Detection

**Tool:** wafw00f

### WAF Identification

The scan identified:

> **Kona SiteDefender (Akamai)**

**Requests:** 2

### Assessment

The result indicates that the target is protected by **Akamai Kona SiteDefender**, an Akamai WAF technology.

The presence of a WAF is an important component of the target's external security architecture and should be considered during subsequent web security testing.

### Evidence

![WAF Detection](screenshots/wafw00f.png)

---

## 4.5 Web Fingerprinting Summary

| Category                 | Result                   |
| ------------------------ | ------------------------ |
| CDN / Edge               | Akamai                   |
| Web Server Identifier    | AkamaiGHost              |
| WAF                      | Akamai Kona SiteDefender |
| HTTP Response            | 403 Forbidden            |
| Origin IP                | Not identified           |
| Origin Technology        | Not identified           |
| TLS                      | TLS 1.3                  |
| Certificate Verification | Successful               |
| HSTS                     | Present                  |

### Overall Assessment

The reconnaissance identified **Akamai CDN/edge infrastructure and Kona SiteDefender WAF protection** in front of the target. HTTP requests to the target resulted in `403 Forbidden` responses, and the origin server could not be identified from the collected responses.

No vulnerability is inferred solely from the observed CDN, WAF, or `403 Forbidden` response.


# 5. WHOIS Enumeration

## Objective

The objective of this phase was to collect publicly available registration and administrative information for the target domain `tesla.com`. WHOIS enumeration can provide information about domain ownership, registrar infrastructure, registration dates, domain protection mechanisms, DNS infrastructure, and DNSSEC status.

**Target:** `tesla.com`

---

## 5.1 Domain Registration Information

| Attribute                   | Value                         |
| --------------------------- | ----------------------------- |
| **Registrar**               | MarkMonitor Inc.              |
| **IANA ID**                 | 292                           |
| **Domain Created**          | 1992-11-04                    |
| **Last Updated**            | 2024-10-02                    |
| **Expiration Date**         | 2026-11-03                    |
| **Registrant Organization** | DNStination INC               |
| **Registrant Location**     | San Francisco, California, US |

### Observation

The domain has been registered since **1992**, indicating a long-established domain presence. The domain is registered through **MarkMonitor Inc.**, an enterprise-focused domain registrar and brand protection provider.

---

## 5.2 Domain Protection

The following domain protection statuses were identified:

```text id="t5wqz2"
clientDeleteProhibited
clientTransferProhibited
clientUpdateProhibited
serverDeleteProhibited
serverTransferProhibited
serverUpdateProhibited
```

### Assessment

The domain has multiple client- and server-side restrictions against unauthorized deletion, transfer, and modification.

These controls provide additional protection against unauthorized domain management actions such as:

* Unauthorized domain transfer
* Unauthorized domain deletion
* Unauthorized registration updates

The presence of these protections represents a positive security control for the domain.

---

## 5.3 DNSSEC Status

**DNSSEC:** `Unsigned`

### Observation

The WHOIS information indicates that DNSSEC is not enabled for the domain.

### Assessment

The absence of DNSSEC means that DNS responses for the domain are not cryptographically authenticated through DNSSEC.

However, **the absence of DNSSEC alone does not constitute a confirmed vulnerability**. The security impact depends on the organization's DNS architecture, threat model, and other DNS security controls.

---

## 5.4 Name Servers

The following name servers were identified:

```text id="5bhrf3"
a1-12.akam.net
a7-66.akam.net
a9-67.akam.net
a10-67.akam.net
a12-64.akam.net
a28-65.akam.net
edns69.ultradns.com
edns69.ultradns.net
edns69.ultradns.org
edns69.ultradns.biz
```

### Assessment

The domain's DNS infrastructure uses **Akamai** and **UltraDNS** name servers, consistent with the distributed DNS and edge infrastructure observed during previous reconnaissance activities.

---

## 5.5 Key Findings

| Finding             | Assessment                                                   |
| ------------------- | ------------------------------------------------------------ |
| Domain Registration | Registered since 1992                                        |
| Registrar           | MarkMonitor Inc.                                             |
| Domain Protection   | Client and server transfer/update/delete protections enabled |
| DNS Infrastructure  | Akamai and UltraDNS                                          |
| DNSSEC              | Unsigned                                                     |
| Registrant          | DNStination INC                                              |

### Overall Assessment

WHOIS enumeration revealed a long-established domain registered through an enterprise registrar with multiple domain protection mechanisms enabled. The domain uses distributed DNS infrastructure involving Akamai and UltraDNS.

DNSSEC was reported as unsigned. This was recorded as an architectural observation rather than a confirmed vulnerability.


## 6. GitHub Enumeration

**Target:** Tesla GitHub Organization

**Source:** [https://github.com/teslamotors](https://github.com/teslamotors?utm_source=chatgpt.com)

### Findings

The official Tesla GitHub organization was reviewed as part of the passive reconnaissance phase. The organization is verified by GitHub and controls the `www.tesla.com` domain.

Public repositories and available organization information were reviewed for potentially sensitive information such as:

* Exposed credentials or API keys
* Configuration files
* Internal hostnames
* Sensitive source code
* Infrastructure information
* Other information that could expand the external attack surface

No security-sensitive information or directly exploitable finding was identified during this review.

### Assessment

The GitHub organization was recorded as part of the target's public attack surface. No actionable security finding was identified from the performed review.
