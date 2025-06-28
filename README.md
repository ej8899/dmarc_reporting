# 📬 Internal DMARC Report Dashboard

This is a private, in-house DMARC reporting tool built for your organization to securely parse, analyze, and visualize DMARC aggregate XML reports (often sent by major providers like Google, Microsoft, Outlook.com).

Unlike most SaaS DMARC dashboards, this keeps **all your sensitive email authentication telemetry inside your environment** — ensuring no data is exposed to external processors.

---

## 📂 File & Directory Structure

```
/dmarc-reporting/
│
├── input/
│   └── *.xml.gz / *.zip / *.xml
│       (Your raw DMARC reports go here)
│
├── output/
│   └── summary.html
│       (Generated interactive HTML report)
│
├── ip_cache.json
│   (Auto-populated local IP geo lookup cache)
│
├── processed_log.json
│   (Tracks processed files to avoid reprocessing)
│
├── dmarc_reporter.py
│   (Main Python script)
│
└── README.md
```

---

## 🚀 Usage

1. **Put your DMARC aggregate files** into the `input/` directory.  
   - Accepts `.xml`, `.xml.gz`, or zipped `.xml` reports.

2. Run:

```bash
python dmarc_reporter.py
```

3. Open `output/summary.html` in your browser for your full interactive report.

---

## 🛠 Automation in M365 / SharePoint

In our environment, we use **Microsoft Power Automate (Flow)** to automatically capture incoming DMARC aggregate reports sent to our compliance mailbox.  

These flows:

- Save the attached `.xml`, `.xml.gz`, or `.zip` files directly into a **SharePoint Document Library**, organized by date.
- This ensures a secure, centralized repository of all raw DMARC files.

---

## 🚀 Automating Python report generation

We further automate this process by:

- Having a scheduled **PowerShell task** run weekly.
- This task:
  - Syncs the latest SharePoint files to the `input/` folder (using `OneDrive sync` or `SharePoint Online PnP PowerShell`).
  - Executes `python dmarc_reporter.py` to process new files and build the updated report.

The generated `output/summary.html` is then:

- Saved back to SharePoint for secure internal viewing, and
- Sent as a static link via internal email for team reviews.

---

✅ This workflow ensures **all DMARC data stays inside existing Microsoft 365 & SharePoint ecosystem**, while still getting robust, private reporting — aligned with your compliance and data residency requirements.

---

## 🔍 What does it show?

- 📊 **Authentication stats:** total messages analyzed, % passed, % failed  
- 📈 **Timeline & priority breakdowns:** stacked daily pass/fail, by domain  
- 🌐 **Geo data:** flags & org lookups for sending IPs  
- ⚠️ **Consumer destination watch:** highlights if your domain shows up in personal email platforms (like gmail.com, hotmail.com)  
- 📝 **Drill-downs:** click any sending domain to see all individual authentication checks, IPs, DKIM/SPF results, explanations, and more.

All designed for exec-friendly at-a-glance summaries plus technical drill-downs.

---

## 🔒 Why build it this way?

- ✅ Keeps your DMARC telemetry **private & on-premises**  
- ✅ No external DMARC SaaS or API processing  
- ✅ Supports security & compliance frameworks (ISO 27001, NIST CSF, GDPR) by limiting exposure of potentially sensitive email metadata.

---

## ⚙️ Requirements

- Python 3.8+
- Only standard libraries used (`os`, `json`, `gzip`, `zipfile`, `xml.etree.ElementTree`, `datetime`, `collections`, `urllib.request`).

---

✅ **Done.**  
Just keep dropping your DMARC reports in `input/`, run the script, and open `summary.html`.  
The tool handles deduping already processed reports, caching IP geolookups, and auto-expands over time.

---

> **Maintainer note:**  
> This project is tailored specifically for your org’s infrastructure & privacy needs.  
> If you need enhancements (like Slack alerts, PDF snapshots, or external IP threat lookups), revisit as your environment evolves.
