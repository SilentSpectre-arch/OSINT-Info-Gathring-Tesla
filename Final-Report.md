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