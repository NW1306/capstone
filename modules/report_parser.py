import xml.etree.ElementTree as ET
from datetime import datetime

def parse_dmarc_report(xml_bytes):
    """Parse DMARC aggregate report XML and return a summary dict."""
    try:
        root = ET.fromstring(xml_bytes)
        print("XML parsed successfully")
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
        return {"error": f"Invalid XML: {e}"}

    # Try without namespace first, then with namespace
    ns = {'ns': 'https://dmarc.org/reporting/aggregate/1.0'}
    
    # Try to find elements without namespace (some reports don't use namespaces)
    org_name = root.findtext('report_metadata/org_name')
    if not org_name:
        org_name = root.findtext('ns:report_metadata/ns:org_name', '', ns)
    
    email = root.findtext('report_metadata/email')
    if not email:
        email = root.findtext('ns:report_metadata/ns:email', '', ns)
    
    report_id = root.findtext('report_metadata/report_id')
    if not report_id:
        report_id = root.findtext('ns:report_metadata/ns:report_id', '', ns)
    
    # Date range
    begin = root.findtext('report_metadata/date_range/begin')
    if not begin:
        begin = root.findtext('ns:report_metadata/ns:date_range/ns:begin', '', ns)
    
    end = root.findtext('report_metadata/date_range/end')
    if not end:
        end = root.findtext('ns:report_metadata/ns:date_range/ns:end', '', ns)

    # Convert timestamps
    try:
        if begin and end:
            begin_dt = datetime.utcfromtimestamp(int(begin)).strftime('%Y-%m-%d %H:%M:%S')
            end_dt = datetime.utcfromtimestamp(int(end)).strftime('%Y-%m-%d %H:%M:%S')
            date_range = f"{begin_dt} to {end_dt}"
        else:
            date_range = "Unknown"
    except:
        date_range = f"{begin} to {end}"

    # Policy published
    domain = root.findtext('policy_published/domain')
    if not domain:
        domain = root.findtext('ns:policy_published/ns:domain', '', ns)
    
    p = root.findtext('policy_published/p')
    if not p:
        p = root.findtext('ns:policy_published/ns:p', '', ns)
    
    sp = root.findtext('policy_published/sp')
    if not sp:
        sp = root.findtext('ns:policy_published/ns:sp', '', ns)

    print(f"Report for domain: {domain}")
    print(f"Policy: {p}")

    # Records
    records = []
    
    # Try without namespace first
    for record in root.findall('record'):
        parse_record(record, records, ns, use_ns=False)
    
    # If no records found, try with namespace
    if not records:
        for record in root.findall('ns:record', ns):
            parse_record(record, records, ns, use_ns=True)

    print(f"Found {len(records)} records")

    # Calculate total emails
    total_emails = sum(r["count"] for r in records)

    return {
        "org_name": org_name or "Unknown",
        "email": email or "Unknown",
        "report_id": report_id or "Unknown",
        "date_range": date_range,
        "domain": domain or "Unknown",
        "policy": p or "none",
        "subdomain_policy": sp or "none",
        "records": records,
        "total_emails": total_emails
    }

def parse_record(record, records, ns, use_ns=False):
    """Helper function to parse a record element"""
    try:
        if use_ns:
            source_ip = record.findtext('ns:row/ns:source_ip', '', ns)
            count = record.findtext('ns:row/ns:count', '0', ns)
            disposition = record.findtext('ns:row/ns:policy_evaluated/ns:disposition', '', ns)
            dkim_result = record.findtext('ns:row/ns:policy_evaluated/ns:dkim', '', ns)
            spf_result = record.findtext('ns:row/ns:policy_evaluated/ns:spf', '', ns)
            header_from = record.findtext('ns:identifiers/ns:header_from', '', ns)
            envelope_to = record.findtext('ns:identifiers/ns:envelope_to', '', ns)
            envelope_from = record.findtext('ns:identifiers/ns:envelope_from', '', ns)
        else:
            source_ip = record.findtext('row/source_ip', '')
            count = record.findtext('row/count', '0')
            disposition = record.findtext('row/policy_evaluated/disposition', '')
            dkim_result = record.findtext('row/policy_evaluated/dkim', '')
            spf_result = record.findtext('row/policy_evaluated/spf', '')
            header_from = record.findtext('identifiers/header_from', '')
            envelope_to = record.findtext('identifiers/envelope_to', '')
            envelope_from = record.findtext('identifiers/envelope_from', '')

        records.append({
            "source_ip": source_ip or "Unknown",
            "count": int(count) if count and count.isdigit() else 0,
            "disposition": disposition or "none",
            "dkim": dkim_result or "unknown",
            "spf": spf_result or "unknown",
            "header_from": header_from or "Unknown",
            "envelope_to": envelope_to or "",
            "envelope_from": envelope_from or ""
        })
    except Exception as e:
        print(f"Error parsing record: {e}")