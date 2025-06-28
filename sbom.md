# 📝 Software Bill of Materials (SBOM)
for Internal DMARC Report Dashboard

---

## 📦 Application Overview
| Component          | Version      | Description                                      |
|--------------------|--------------|--------------------------------------------------|
| dmarc_reporter.py   | internal     | Parses DMARC aggregate XML/GZ/ZIP, generates HTML summary dashboard |

---

## 🛠 Dependencies (Python Standard Library Only)
| Package / Module          | Version | Source  | Notes                          |
|---------------------------|---------|---------|--------------------------------|
| os                        | stdlib  | Python  | Filesystem & directory mgmt    |
| json                      | stdlib  | Python  | JSON parsing & serialization   |
| gzip                      | stdlib  | Python  | GZ decompression               |
| zipfile                   | stdlib  | Python  | ZIP decompression              |
| xml.etree.ElementTree     | stdlib  | Python  | XML parsing                    |
| datetime                  | stdlib  | Python  | Date/time conversions          |
| collections               | stdlib  | Python  | defaultdicts, counters         |
| urllib.request            | stdlib  | Python  | HTTP requests for IP API lookups |

---

## 🌐 External Services / Data Sources
| Service              | Purpose                          | Notes                               |
|----------------------|---------------------------------|-------------------------------------|
| ip-api.com (http API) | IP geo & org lookup             | No data sent beyond IP address; cached locally in `ip_cache.json` |
| flagcdn.com           | Displays small country flags   | Pure image retrieval, no data sharing |

---

## 📂 Outputs & Storage
| File                     | Purpose                                |
|--------------------------|---------------------------------------|
| `output/summary.html`     | Final DMARC interactive HTML report   |
| `processed_log.json`      | Keeps track of processed files to avoid reprocessing |
| `ip_cache.json`           | Local cache of IP geo lookups         |

---

## 🔒 Security / Privacy Notes
✅ All DMARC telemetry is processed **entirely in your environment**, no email metadata is sent to external SaaS DMARC processors.  
✅ The only outbound lookups are **single IPs** to ip-api.com, with results cached locally.

---

## 📅 Last Generated SBOM
- **Date:** 2025-06-27
- **Generated for:** Internal compliance / security reference
