import os
import json
import gzip
import zipfile
import xml.etree.ElementTree as ET
import urllib.request

from datetime import datetime, timezone
from collections import defaultdict
from collections import OrderedDict

INPUT_DIR = 'input'
OUTPUT_FILE = 'output/summary.html'
LOG_FILE = 'processed_log.json'

# Track unauthenticated sources
source_counter = defaultdict(int)

consumer_domains = [
  "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "aol.com", 
  "icloud.com", "me.com", "live.com", "msn.com", 
  "protonmail.com", "zoho.com", "gmx.com", "mail.com", 
  "yandex.com", "tutanota.com", "hushmail.com"
]
consumer_counter = defaultdict(int)

known_orgs = ['google', 'microsoft', 'proofpoint', 'barracuda', 'secureserver']
uncommon_ips = defaultdict(int)



#
# misc helpers
#
def get_authenticated_as(entry):
    return entry.get('spf_auth_domain') or entry.get('dkim_auth_domain') or 'Unknown'

def summarize_status(entry):
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        return '✅ Pass'
    else:
        return '❌ Fail'

def summarize_result(entry):
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        return '✅ Verified sender – authentication passed'
    else:
        return '🔓 Unverified sender – not authorized'

def explain_check(label, result, domain=None):
    if result == 'pass':
        return f"✅ {label} passed – sender was authorized"
    elif result == 'fail':
        return f"❌ {label} failed – sender was not authorized"
    elif result == 'softfail':
        return f"⚠️ {label} soft fail – sender was probably not authorized"
    else:
        return f"❔ {label} result unknown"

def friendly_explanation(entry):
    spf_domain = entry.get('spf_auth_domain') or 'unknown'
    source_ip = entry.get('source_ip') or 'unknown'
    from_domain = entry.get('header_from') or 'unknown'
    dkim_result = entry.get('dkim_result')
    spf_result = entry.get('spf_result')
    count = int(entry.get('count', 1))
    known_shared = any(k in spf_domain.lower() for k in ['google', 'microsoft', 'outlook', 'secureserver', 'barracuda', 'proofpoint'])

    if dkim_result == 'pass' and spf_result == 'pass':
        return "This message passed both DKIM and SPF authentication checks. No issues were detected."
    if dkim_result == 'pass' and spf_result != 'pass':
        return "This message was authenticated using DKIM, though SPF failed. Often due to forwarding, usually not a concern."
    if spf_result == 'fail' and known_shared:
        return f"This message failed SPF but came through {spf_domain}, which uses shared infrastructure. Forwarding can cause this."
    if dkim_result == 'fail' and spf_result == 'fail':
        if known_shared:
            return f"This message failed both SPF and DKIM but was routed via {spf_domain}, a known platform. Likely harmless relay."
        elif count == 1:
            return "This message failed authentication once. One-offs often come from replies, auto-forwards or misconfigs."
        else:
            return f"This message failed SPF/DKIM from {spf_domain} claiming to be {from_domain}. Multiple instances may need review."
    return "This message failed authentication checks. Often caused by forwarding or unauthenticated services. Not necessarily malicious."



#
# --- GEOLOOKUP + CACHING ---
#
GEO_CACHE_FILE = 'ip_cache.json'

# Load the geo cache
if os.path.exists(GEO_CACHE_FILE):
    with open(GEO_CACHE_FILE, 'r') as f:
        ip_cache = json.load(f)
else:
    ip_cache = {}


#
# lookup IP by ip-api.com
#
def lookup_ip_info(ip):
    if ip in ip_cache:
        return ip_cache[ip]

    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}") as response:
            data = json.loads(response.read().decode())

        if data['status'] == 'success':
            result = {
                'country': data['country'],
                'countryCode': data['countryCode'].lower(),
                'org': data.get('org', ''),
            }
        else:
            result = {'country': 'Unknown', 'countryCode': '', 'org': ''}
    except Exception as e:
        print(f"IP lookup failed for {ip}: {e}")
        result = {'country': 'Unknown', 'countryCode': '', 'org': ''}

    ip_cache[ip] = result
    return result

#
# Load or initialize processed files log
#
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'r') as f:
        processed_files = set(json.load(f))
else:
    processed_files = set()

records = []

def friendly_explanation(entry):
    spf_domain = entry.get('spf_auth_domain') or 'unknown'
    source_ip = entry.get('source_ip') or 'unknown'
    from_domain = entry.get('header_from') or 'unknown'
    dkim_result = entry.get('dkim_result')
    spf_result = entry.get('spf_result')
    dkim_auth_domain = entry.get('dkim_auth_domain')
    count = int(entry.get('count', 1))
    is_google = source_ip.startswith("209.85.") or "google" in spf_domain.lower()
    is_microsoft = source_ip.startswith("40.") or "outlook" in spf_domain.lower() or "microsoft" in spf_domain.lower()
    known_shared = any(k in spf_domain.lower() for k in ['google', 'microsoft', 'outlook', 'secureserver', 'barracuda', 'proofpoint'])

    # If both DKIM and SPF pass
    if dkim_result == 'pass' and spf_result == 'pass':
        return "This message passed both DKIM and SPF authentication checks. No issues were detected."

    # If DKIM passes but SPF fails
    if dkim_result == 'pass' and spf_result != 'pass':
        return "This message was successfully authenticated using DKIM, even though SPF failed. This is common with forwarded or relayed email and is not typically a concern."


    # SPF failed but known infrastructure
    if spf_result == 'fail' and known_shared:
        return (
            f"This message failed SPF, but was handled by {spf_domain}, which uses shared infrastructure (e.g., Gmail, Microsoft 365, or mail filters). "
            f"SPF failures are common in forwarded or replied messages and usually do not indicate spoofing."
        )

    # Both fail, known domain, low frequency
    if dkim_result == 'fail' and spf_result == 'fail':
        if known_shared:
            return (
                f"This message failed both SPF and DKIM but was routed through {spf_domain}, a known mail platform. "
                "Forwarding or relays may have caused authentication to break. This is not inherently malicious."
            )
        elif count == 1:
            return (
                "This message failed authentication, but only appeared once in this reporting window. "
                "One-time failures like this are common with auto-replies, forwarding, or unauthenticated tools and don't require immediate concern."
            )
        else:
            return (
                f"This message failed both SPF and DKIM and was sent by {spf_domain} claiming to be {from_domain}. "
                "It has occurred multiple times and may reflect a misconfiguration or unauthorized use."
            )

    return "This message failed authentication checks. It may be caused by forwarding, replies, or external services that aren't yet authorized. This is not necessarily a spoof or attack."



def decompress_and_parse(file_path):
    try:
        if file_path.endswith('.gz'):
          try:
              with gzip.open(file_path, 'rb') as f:
                  return ET.parse(f).getroot()
          except OSError:
              # Fall back if not truly gzipped
              with open(file_path, 'rb') as f:
                  return ET.parse(f).getroot()
        elif file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path) as z:
                for name in z.namelist():
                    if name.endswith('.xml'):
                        with z.open(name) as f:
                            return ET.parse(f).getroot()
        elif file_path.endswith('.xml'):
            return ET.parse(file_path).getroot()
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return None

def extract_records(root):
    entries = []
    try:
        meta = root.find('report_metadata')
        org = meta.findtext('org_name', default="Unknown")
        report_id = meta.findtext('report_id')
        begin = datetime.fromtimestamp(int(meta.find('date_range/begin').text), timezone.utc).strftime('%Y-%m-%d')
        end = datetime.fromtimestamp(int(meta.find('date_range/end').text), timezone.utc).strftime('%Y-%m-%d')

        for record in root.findall('record'):
            row = record.find('row')
            auth = record.find('auth_results')
            spf = auth.find('spf') if auth is not None else None
            dkim = auth.find('dkim') if auth is not None else None
            envelope_to = record.find('identifiers/envelope_to')

            source_ip = row.findtext('source_ip')
            geo = lookup_ip_info(source_ip)

            entries.append({
                'date_start': begin,
                'date_end': end,  # <-- required for HTML sorting
                'org_name': org,
                'report_id': report_id,
                'header_from': record.find('identifiers/header_from').text,
                'source_ip': row.findtext('source_ip'),
                'count': row.findtext('count'),
                'spf_result': row.find('policy_evaluated/spf').text,
                'dkim_result': row.find('policy_evaluated/dkim').text,
                'disposition': row.find('policy_evaluated/disposition').text,
                'spf_auth_domain': spf.findtext('domain') if spf is not None else '',
                'spf_auth_result': spf.findtext('result') if spf is not None else '',
                'dkim_auth_domain': dkim.findtext('domain') if dkim is not None else '',
                'dkim_auth_result': dkim.findtext('result') if dkim is not None else '',
                'geo_country': geo['country'],
                'geo_code': geo['countryCode'],
                'geo_org': geo['org'],
                'envelope_to': envelope_to.text if envelope_to is not None else 'Unknown',
            })
    except Exception as e:
        print(f"Failed to extract record: {e}")
    return entries

def get_authenticated_as(entry):
    return entry.get('spf_auth_domain') or entry.get('dkim_auth_domain') or 'Unknown'

def summarize_status(entry):
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        return '✅ Pass'
    else:
        return '❌ Fail'

def summarize_result(entry):
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        return '✅ Verified sender – authentication passed'
    else:
        return '🔓 Unverified sender – not authorized'

# Main processing
for filename in os.listdir(INPUT_DIR):
    file_path = os.path.join(INPUT_DIR, filename)
    if filename in processed_files:
        continue

    root = decompress_and_parse(file_path)
    if root is not None:
        records.extend(extract_records(root))
        processed_files.add(filename)

for entry in records:
    if 'auth_source_key' not in entry:
        entry['auth_source_key'] = f"{entry.get('source_ip', '')}|{entry.get('spf_auth_domain') or entry.get('dkim_auth_domain') or 'unknown'}"

for entry in records:
    to_domain = (entry.get('envelope_to') or '').lower()
    if to_domain in consumer_domains:
        consumer_counter[to_domain] += int(entry.get('count', 1))

for entry in records:
    org = (entry.get('geo_org') or '').lower()
    if not any(known in org for known in known_orgs):
        uncommon_ips[entry['source_ip']] += int(entry.get('count', 1))     

# Assign priority levels based on frequency of unauthenticated source
for entry in records:
    # Fully authenticated? No priority needed
    if entry.get('spf_result') == 'pass' and entry.get('dkim_result') == 'pass':
        entry['priority'] = '✅ N/A – Message fully authenticated'
    else:
        count = source_counter.get(entry.get('auth_source_key'), 1)
        if count > 10:
            entry['priority'] = '🔴 High – Based on frequency of similar unauthenticated messages.'
        elif count > 3:
            entry['priority'] = '🟠 Medium – Based on frequency of similar unauthenticated messages.'
        else:
            entry['priority'] = '🟢 Low – Based on frequency of similar unauthenticated messages.'


with open(GEO_CACHE_FILE, 'w') as f:
    json.dump(ip_cache, f, indent=2)


# Group by (auth domain + IP)
grouped_domains = {}

for entry in records:
    domain = entry.get('spf_auth_domain') or entry.get('dkim_auth_domain') or 'Unknown'
    if domain not in grouped_domains:
        grouped_domains[domain] = {
            'total': 0,
            'auth_pass': 0,
            'auth_fail': 0,
            'dates': set(),
            'recipients': set(),
            'details': []
        }

    grouped_domains[domain]['total'] += int(entry.get('count', 1))
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        grouped_domains[domain]['auth_pass'] += int(entry.get('count', 1))
    else:
        grouped_domains[domain]['auth_fail'] += int(entry.get('count', 1))
    grouped_domains[domain]['dates'].add(entry['date_end'])
    grouped_domains[domain]['recipients'].add(entry.get('envelope_to') or 'Unknown')
    grouped_domains[domain]['details'].append(entry)



#
# watch list generator
#
watch_html = ""

if consumer_counter or uncommon_ips:
    watch_html += """
<div style="
  margin: 20px 0;
  padding: 15px;
  border: 1px solid #ccc;
  border-radius: 8px;
  background: #eceff4; /* nord light */
  font-size: 15px;
  line-height: 1.5;
">
"""
    if consumer_counter:
        watch_html += "<strong>⚠️ Consumer Destination Watch:</strong><br>"
        for domain, count in consumer_counter.items():
            watch_html += f"• {domain} — {count} messages<br>"

    if uncommon_ips:
        watch_html += "<br><strong>🕵️ Uncommon Sending IPs:</strong><br>"
        for ip, count in uncommon_ips.items():
            watch_html += f"• {ip} — {count} messages<br>"

    watch_html += "</div>"


#
# group table generator
#
grouped_table_html = """
<h2>🔍 Sending Domains Summary</h2>
<table>
<thead>
<tr>
  <th>Auth Domain</th>
  <th>Total</th>
  <th>✅ Auth</th>
  <th>❌ Fail</th>
</tr>
</thead>
<tbody>
"""

for domain, data in grouped_domains.items():
    auth_pct = round((data['auth_pass'] / data['total']) * 100) if data['total'] else 0
    fail_pct = 100 - auth_pct
    date_range = f"{min(data['dates'])}–{max(data['dates'])}" if data['dates'] else ''
    div_id = f"details_{domain.replace('.', '_')}"

    grouped_table_html += f"""
<tr class="group-row" onclick="toggleDetails('{div_id}')">
  <td>{domain}</td>
  <td>{data['total']}</td>
  <td>{data['auth_pass']} ({auth_pct}%)</td>
  <td>{data['auth_fail']} ({fail_pct}%)</td>
</tr>
<tr class="details" id="{div_id}" style="display:none;">
  <td colspan="5">
    <table class="details-table">
      <thead>
        <tr>
          <th>Status</th><th>Date</th><th>Claimed From</th><th>Sent By</th><th>Auth As</th><th>Reported By</th><th>Details</th>
        </tr>
      </thead>
      <tbody>
    """

    for idx, entry in enumerate(data['details']):
        detail_id = f"{div_id}_entry_{idx}"
        authenticated_as = get_authenticated_as(entry)
        row_class = "fail-row" if summarize_status(entry) == '❌ Fail' else ""
        # summary line
        grouped_table_html += f"""

<tr onclick="toggleDetails('{detail_id}')" class="record-row {row_class}">
  <td>{summarize_status(entry)}</td>
  <td>{entry['date_end']}</td>
  <td>{entry['header_from']}</td>
  <td>{'<img src="https://flagcdn.com/16x12/{}.png" width="16" height="12">'.format(entry['geo_code']) if entry.get('geo_code') else ''}&nbsp;{entry['source_ip']}</td>
  <td>{authenticated_as}</td>
  <td>{entry['envelope_to']}</td>
  <td>🔎 View</td>
</tr>
<tr class="details" id="{detail_id}" style="display:none;">
  <td colspan="7">
    <table class="item-details-table">
      <tr><td>📅 <strong>Date</strong></td><td>{entry['date_end']}</td></tr>
      <tr><td>📬 <strong>Claimed Sender</strong></td><td>{entry['header_from']}</td></tr>
      <tr><td>🔐 <strong>Authenticated As</strong></td><td>{authenticated_as}</td></tr>
      <tr><td>📤 <strong>Sent From</strong></td>
      <td>
        {'<img src="https://flagcdn.com/16x12/{}.png" width="16" height="12">'.format(entry['geo_code']) if entry.get('geo_code') else ''}
        &nbsp;{entry['source_ip']} ({entry['geo_org']}, {entry['geo_country']})
      </td></tr>
      <tr><td>✉️ <strong>Reported By</strong></td><td>{entry['envelope_to']}</td></tr>
      <tr><td>🔍 <strong>SPF Check</strong></td><td>{explain_check('SPF', entry['spf_auth_result'], entry['spf_auth_domain'])}</td></tr>
      <tr><td>📝 <strong>DKIM Check</strong></td><td>{explain_check('DKIM', entry['dkim_auth_result'], entry['dkim_auth_domain'])}</td></tr>
      <tr><td>📜 <strong>DMARC Disposition</strong></td><td>{entry['disposition']}</td></tr>
      <tr><td>📦 <strong>Message Count</strong></td><td>{entry['count']}</td></tr>
      <tr><td>🧠 <strong>Explanation</strong></td><td>{friendly_explanation(entry)}</td></tr>
      <tr><td>🔗 <strong>VirusTotal</strong></td><td><a href="https://www.virustotal.com/gui/ip-address/{entry['source_ip']}/detection" target="_blank">Check {entry['source_ip']} on VirusTotal</a></td></tr>
      {"<tr><td>🚦 <strong>Priority</strong></td><td>" + entry['priority'] + "</td></tr>" if entry.get('priority') else ""}
    </table>
  </td>
</tr>
"""
    grouped_table_html += "</tbody></table></td></tr>"

grouped_table_html += "</tbody></table>"


#
# --- Summary Stats ---
#
report_count = len(set(r['report_id'] for r in records if 'report_id' in r))
total_msgs = sum(int(r.get('count', 1)) for r in records)
failed_msgs = sum(
    int(r.get('count', 1)) for r in records
    if r.get('spf_result') != 'pass' or r.get('dkim_result') != 'pass'
)
auth_msgs = total_msgs - failed_msgs
auth_pct = round((auth_msgs / total_msgs) * 100) if total_msgs > 0 else 0
fail_pct = 100 - auth_pct

summary_html = f"""
<div style="margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #f9f9f9; font-size: 16px;">
  <strong>🔢 Overall Summary</strong><br>
  📦 Reports Processed: {report_count}<br>
  📨 Messages Analyzed: {total_msgs}<br>
  ✅ Authenticated: {auth_msgs} ({auth_pct}%)<br>
  ❌ Failed Auth: {failed_msgs} ({fail_pct}%)
</div>
"""


# --- Chart Data Prep ---
senders_count = defaultdict(int)
receivers_count = defaultdict(int)

for entry in records:
    sender = entry.get('spf_auth_domain') or entry.get('dkim_auth_domain') or 'Unknown'
    sender = sender.lower()
    senders_count[sender] += int(entry.get('count', 1))

    receiver = entry.get('org_name', 'Unknown')
    receivers_count[receiver] += int(entry.get('count', 1))





# --- Chart 3: Auth Status Breakdown ---
auth_status_counter = defaultdict(int)
for r in records:
    count = int(r.get('count', 1))
    spf = r.get('spf_result', '').lower()
    dkim = r.get('dkim_result', '').lower()

    if spf == 'pass' and dkim == 'pass':
        auth_status_counter['Authenticated'] += count
    elif spf in ('fail', 'softfail') or dkim in ('fail', 'softfail'):
        auth_status_counter['Failed'] += count
    else:
        auth_status_counter['Partial / Other'] += count

auth_status_data_js = [["Status", "Messages"]] + [[k, v] for k, v in auth_status_counter.items()]


# --- Chart 4: Priority Breakdown ---
priority_counter = defaultdict(int)
for r in records:
    count = int(r.get('count', 1))
    label = r.get('priority', 'Unknown')
    priority_counter[label] += count

priority_data_js = [["Priority", "Messages"]] + [[k, v] for k, v in priority_counter.items()]


# DMARC timeline summary (last 30 days)
timeline_counter = defaultdict(lambda: {"pass": 0, "fail": 0})

for entry in records:
    date = entry['date_end']
    passed = entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass'
    if passed:
        timeline_counter[date]["pass"] += int(entry.get('count', 1))
    else:
        timeline_counter[date]["fail"] += int(entry.get('count', 1))

# Keep only last 30 days
sorted_dates = sorted(timeline_counter.keys())[-30:]
auth_timeline_data_js = [["Date", "Pass", "Fail"]] + [
    [date, timeline_counter[date]["pass"], timeline_counter[date]["fail"]]
    for date in sorted_dates
]


# Save processed file list
with open(LOG_FILE, 'w') as f:
    json.dump(list(processed_files), f)

# Output HTML
# Sort records by most recent date first
# Sort by most recent report date
records = sorted(records, key=lambda r: r['date_end'], reverse=True)

def summarize_status(entry):
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        return '✅ Pass'
    else:
        return '❌ Fail'

def summarize_result(entry):
    if entry['spf_result'] == 'pass' and entry['dkim_result'] == 'pass':
        return '✅ Verified sender – authentication passed'
    else:
        return '🔓 Unverified sender – not authorized'

def explain_check(label, result, domain=None):
    if result == 'pass':
        return f"✅ {label} passed – sender was authorized"
    elif result == 'fail':
        return f"❌ {label} failed – sender was not authorized"
    elif result == 'softfail':
        return f"⚠️ {label} soft fail – sender was probably not authorized"
    else:
        return f"❔ {label} result unknown"

def get_authenticated_as(entry):
    return entry['spf_auth_domain'] or entry['dkim_auth_domain'] or 'Unknown'




#
# Convert to Google Charts JS format
#
senders_data_js = [["Sender", "Messages"]] + [[str(k), int(v)] for k, v in senders_count.items()]

# Limit to top x receivers by message count
top_receivers = sorted(receivers_count.items(), key=lambda x: x[1], reverse=True)[:10]
receivers_data_js = [["Receiver", "Reports"]] + [[str(k), int(v)] for k, v in top_receivers]

auth_status_data_js = [["Auth Status", "Count"]] + [[str(k), int(v)] for k, v in auth_status_counter.items()]

priority_label_map = {
    '✅ N/A – Message fully authenticated': 'N/A',
    '🟢 Low – Based on frequency of similar unauthenticated messages.': 'Low',
    '🟠 Medium – Based on frequency of similar unauthenticated messages.': 'Medium',
    '🔴 High – Based on frequency of similar unauthenticated messages.': 'High'
}


priority_counter = defaultdict(int)
for entry in records:
    label = entry.get('priority', '')
    short_label = priority_label_map.get(label, 'Other')
    priority_counter[short_label] += int(entry.get('count', 1))

priority_data_js = [["Priority", "Messages"]] + [[k, int(v)] for k, v in priority_counter.items()]


style_and_script = """
<style>
body { font-family: 'Inter', Arial, sans-serif; padding: 20px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
th, td { padding: 8px 12px; border: 1px solid #ccc; }
th { background: #f5f5f5; }
.summary-row:hover { background: #f0f8ff; cursor: pointer; }
.details { display: none; background: #fdfdfd; border-left: 4px solid #ccc; }
.pass { color: green; font-weight: bold; }
.fail { color: red; font-weight: bold; }
.details-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 10px;
}
.details-table tr.fail-row {
  background: #f2e7e9;
}
.details-table td {
  padding: 6px 8px;
  vertical-align: top;
  border-bottom: 1px solid #eee;
}
.details-table td:first-child {
  font-weight: bold;
  width: 180px;
  white-space: nowrap;
}
.chart-card {
  background: #ECEFF4;
  border: 1px solid #D8DEE9;
  border-radius: 8px;
  padding: 15px;
  box-shadow: 0 2px 4px rgba(76, 86, 106, 0.1);
}
.group-row:hover, .record-row:hover {
  background: #e5e9f0; /* nord polar night light */
  cursor: pointer;
}
.item-details-table {
  background: #eceff4; /* subtle Nord light background for details */
}

</style>
<script>
function toggleDetails(id) {
  const thisRow = document.getElementById(id);
  const isOpen = (thisRow.style.display === 'table-row');

  if (id.startsWith('details_') && !id.includes('_entry_')) {
    // close all top-level
    document.querySelectorAll('tr.details').forEach(row => {
      if (!row.id.includes('_entry_')) row.style.display = 'none';
    });
  }
  if (id.includes('_entry_')) {
    // close all record-level
    const parentTable = thisRow.closest('table.details-table');
    parentTable.querySelectorAll('tr.details').forEach(row => {
      if (row.id.includes('_entry_')) row.style.display = 'none';
    });
  }

  // toggle this one: if was closed, open it; if open, close it
  thisRow.style.display = (isOpen ? 'none' : 'table-row');
}
</script>

"""

summary_html = f"""
<div style="margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #f9f9f9; font-size: 16px;">
  <strong>🔢 Overall Summary</strong><br>
  📦 Reports Processed: {report_count} | 📨 Messages Analyzed: {total_msgs}<br>
  ✅ Authenticated: {auth_msgs} ({auth_pct}%) |  ❌ Failed Auth: {failed_msgs} ({fail_pct}%)
</div>
"""

chart_html = f"""
<!-- Google Charts Loader -->
<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
<script type="text/javascript">
  google.charts.load("current", {{packages:["corechart", "bar"]}});
  google.charts.setOnLoadCallback(drawCharts);

  function drawCharts() {{
    var sendersData = google.visualization.arrayToDataTable({json.dumps(senders_data_js)});
    var sendersChart = new google.visualization.PieChart(document.getElementById('senders_chart'));
    sendersChart.draw(sendersData, {{
      chartArea: {{ width: '80%' }},
      title: 'Senders (Sending Sources)',
      pieHole: 0.4, legend: {{ position: 'right' }}
    }});

    var receiversData = google.visualization.arrayToDataTable({json.dumps(receivers_data_js)});
    var receiversChart = new google.visualization.BarChart(document.getElementById('receivers_chart'));
    receiversChart.draw(receiversData, {{
      title: 'Receivers (Reporting Destinations)',
      chartArea: {{ width: '80%' }},
      legend: {{ position: 'none' }},
      hAxis: {{ minValue: 0 }}
    }});

    /* var authData = google.visualization.arrayToDataTable({json.dumps(auth_status_data_js)});
    var authChart = new google.visualization.PieChart(document.getElementById('auth_chart'));
    authChart.draw(authData, {{
      title: 'Authentication Status',
      chartArea: {{ width: '80%' }},
      pieHole: 0.4, legend: {{ position: 'right' }}
    }}); */

  var timelineData = google.visualization.arrayToDataTable({json.dumps(auth_timeline_data_js)});
  var timelineOptions = {{
    title: 'Authentication Results by Day',
    isStacked: true,
    chartArea: {{ width: '80%' }},
    hAxis: {{ title: 'Date' }},
    vAxis: {{ title: 'Message Count' }},
    colors: ['#2ecc71', '#e74c3c']
  }};
  var timelineChart = new google.visualization.ColumnChart(document.getElementById('auth_timeline_chart'));
  timelineChart.draw(timelineData, timelineOptions);


    var priorityData = google.visualization.arrayToDataTable({json.dumps(priority_data_js)});
    var priorityChart = new google.visualization.PieChart(document.getElementById('priority_chart'));
    priorityChart.draw(priorityData, {{
      title: 'Message Priority Breakdown',
      pieHole: 0.4,
      legend: {{ position: 'right' }},
      colors: ['#2ecc71', '#f1c40f', '#e67e22', '#e74c3c']
    }});
  }}
</script>

<!-- 2x2 Chart Layout -->
<div style="display: flex; gap: 20px; margin-bottom: 20px; width: 100%;">
  <div class="chart-card" style="flex: 1;">
    <div id="senders_chart" style="width: 100%; height: 350px;"></div>
  </div>
  <div class="chart-card" style="flex: 1;">
    <div id="receivers_chart" style="width: 100%; height: 350px;"></div>
  </div>
</div>
<div style="display: flex; gap: 20px; width: 100%;">
  <!-- <div class="chart-card" style="flex: 1;">
    <div id="auth_chart" style="width: 100%; height: 350px;"></div>
  </div> -->
  <div class="chart-card" style="flex: 1;">
    <div id="auth_timeline_chart" style="width: 100%; height: 350px;"></div>
  </div>
  <div class="chart-card" style="flex: 1;">
    <div id="priority_chart" style="width: 100%; height: 350px;"></div>
  </div>
</div>


"""




html_output = f"""
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><title>DMARC Report</title>
{style_and_script}
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">

</head><body>
<h1 style="margin-bottom: 0;">📬 DMARC Report Summary</h1>
<p style="font-size: 0.95em; color: #666; margin-top: 4px;">
  Covering {records[-1]['date_start']} to {records[0]['date_end']} 
  ({(datetime.strptime(records[0]['date_end'], '%Y-%m-%d') - datetime.strptime(records[-1]['date_start'], '%Y-%m-%d')).days + 1} days)
</p>


{summary_html}
{chart_html}

{watch_html}

{grouped_table_html}



</body></html>
"""

# Save final report
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    f.write(html_output)

print(f"✅ Report generated: {OUTPUT_FILE}")
