import re
import dkim
from email import policy
from email.parser import BytesParser
from . import dns_utils
import traceback

def extract_headers(msg):
    """Extract From domain, Return-Path, and sending IP from email message."""
    try:
        # Get From address
        from_hdr = msg.get('From', '')
        print(f"From header: {from_hdr}")
        
        # Extract email from From field
        from_match = re.search(r'<(.+@.+)>', from_hdr) 
        if not from_match:
            from_match = re.search(r'([\w\.-]+@[\w\.-]+)', from_hdr)
        
        from_addr = from_match.group(1) if from_match else from_hdr
        from_domain = from_addr.split('@')[-1] if '@' in from_addr else None
        print(f"From domain: {from_domain}")

        # Get Return-Path
        return_path = msg.get('Return-Path', '')
        if return_path.startswith('<') and return_path.endswith('>'):
            return_path = return_path[1:-1]
        return_path_domain = return_path.split('@')[-1] if '@' in return_path else from_domain
        print(f"Return-Path domain: {return_path_domain}")

        # Get sending IP from Received headers
        received = msg.get_all('Received', [])
        ip = None
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        for rec in received:
            print(f"Received header: {rec[:100]}...")  # Print first 100 chars
            ips = re.findall(ip_pattern, rec)
            if ips:
                ip = ips[0]
                print(f"Found IP: {ip}")
                break
        
        if not ip:
            print("No IP found in Received headers")
            
        return from_domain, return_path_domain, ip
        
    except Exception as e:
        print(f"Error in extract_headers: {e}")
        traceback.print_exc()
        return None, None, None

def get_spf_record(domain):
    """Enhanced SPF record extraction with include following"""
    try:
        print(f"Looking up SPF for {domain}")
        for txt in dns_utils.query_txt(domain):
            if txt.startswith('v=spf1'):
                print(f"Found SPF: {txt}")
                
                # Check for includes
                includes = re.findall(r'include:([^\s]+)', txt)
                if includes:
                    print(f"Found includes: {includes}")
                    # Optionally fetch included records
                    for include_domain in includes:
                        include_records = dns_utils.query_txt(include_domain)
                        for inc_txt in include_records:
                            if inc_txt.startswith('v=spf1'):
                                print(f"Included SPF from {include_domain}: {inc_txt}")
                                # Merge or process included record
                
                return txt
        print("No SPF record found")
        return None
    except Exception as e:
        print(f"Error getting SPF: {e}")
        return None

def check_spf(ip, spf_record):
    """Very basic SPF check (ip4 only)."""
    try:
        if not spf_record or not ip:
            print(f"SPF check: missing data - ip={ip}, record={spf_record}")
            return False
        
        print(f"Checking SPF: IP={ip} against {spf_record[:100]}...")
        ip4_pattern = r'ip4:([0-9.]+)'
        allowed_ips = re.findall(ip4_pattern, spf_record)
        print(f"Allowed IPs: {allowed_ips}")
        
        result = ip in allowed_ips
        print(f"SPF result: {result}")
        return result
    except Exception as e:
        print(f"Error in SPF check: {e}")
        return False

def get_dmarc_record(domain):
    """Fetch DMARC record from _dmarc.domain."""
    try:
        dmarc_domain = f'_dmarc.{domain}'
        print(f"Looking up DMARC for {dmarc_domain}")
        
        for txt in dns_utils.query_txt(dmarc_domain):
            if txt.startswith('v=DMARC1'):
                print(f"Found DMARC: {txt[:100]}...")
                return txt
        print("No DMARC record found")
        return None
    except Exception as e:
        print(f"Error getting DMARC: {e}")
        return None

def parse_dmarc(record):
    """Parse DMARC tags into dict."""
    try:
        if not record:
            return {}
        
        tags = record.split(';')
        dmarc = {}
        for tag in tags:
            tag = tag.strip()
            if '=' in tag:
                k, v = tag.split('=', 1)
                dmarc[k.strip()] = v.strip()
        print(f"Parsed DMARC: {dmarc}")
        return dmarc
    except Exception as e:
        print(f"Error parsing DMARC: {e}")
        return {}

def verify_dkim(msg_bytes):
    """Verify DKIM signature using dkimpy."""
    try:
        print("Verifying DKIM signature...")
        if dkim.verify(msg_bytes):
            sig = dkim.dkim_signature(msg_bytes)
            if sig:
                domain = sig.domain.decode()
                print(f"DKIM valid, domain: {domain}")
                return True, domain
        print("DKIM verification failed or no signature")
        return False, None
    except Exception as e:
        print(f"Error in DKIM verification: {e}")
        return False, None

def classify(spf_pass, dkim_pass, spf_aligned, dkim_aligned, dmarc_policy):
    """Return verdict and reason."""
    try:
        print(f"Classifying: SPF pass={spf_pass}, DKIM pass={dkim_pass}")
        print(f"Alignment: SPF aligned={spf_aligned}, DKIM aligned={dkim_aligned}")
        print(f"DMARC policy: {dmarc_policy}")
        
        if not dmarc_policy:
            if spf_pass or dkim_pass:
                return "Legitimate", "No DMARC policy, but at least one auth passed."
            else:
                return "Suspicious", "No DMARC policy and both SPF/DKIM failed."

        policy = dmarc_policy.get('p', 'none')
        auth_pass = (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned)

        if policy == 'reject':
            if auth_pass:
                return "Legitimate", "DMARC reject policy but authentication passed."
            else:
                return "Spoofed", "DMARC reject policy and authentication failed."
        elif policy == 'quarantine':
            if auth_pass:
                return "Legitimate", "DMARC quarantine policy but authentication passed."
            else:
                return "Suspicious", "DMARC quarantine policy and authentication failed."
        else:  # 'none'
            if auth_pass:
                return "Legitimate", "DMARC none policy and authentication passed."
            else:
                return "Suspicious", "DMARC none policy but authentication failed."
    except Exception as e:
        print(f"Error in classification: {e}")
        return "Error", f"Classification error: {e}"

def analyze_email(file_bytes):
    """Main function: accept email bytes, return analysis dict."""
    try:
        print("=" * 50)
        print("Starting email analysis")
        print("=" * 50)
        
        # Parse email
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
        print("Email parsed successfully")
        
        # Extract headers
        from_domain, return_path_domain, sending_ip = extract_headers(msg)
        
        if not from_domain:
            return {"error": "Could not determine From domain."}
        
        print(f"Analysis target: From={from_domain}, Return-Path={return_path_domain}, IP={sending_ip}")

        # SPF
        spf_record = get_spf_record(return_path_domain)
        spf_pass = check_spf(sending_ip, spf_record) if sending_ip else False

        # DKIM
        dkim_pass, dkim_domain = verify_dkim(file_bytes)

        # DMARC
        dmarc_record = get_dmarc_record(from_domain)
        dmarc_policy = parse_dmarc(dmarc_record)

        # Alignment
        spf_aligned = (return_path_domain == from_domain)
        dkim_aligned = (dkim_domain == from_domain) if dkim_domain else False

        verdict, reason = classify(spf_pass, dkim_pass, spf_aligned, dkim_aligned, dmarc_policy)

        result = {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "sending_ip": sending_ip,
            "spf_record": spf_record,
            "spf_pass": spf_pass,
            "dkim_pass": dkim_pass,
            "dkim_domain": dkim_domain,
            "dmarc_record": dmarc_record,
            "dmarc_policy": dmarc_policy.get('p', 'none') if dmarc_policy else 'none',
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "verdict": verdict,
            "reason": reason
        }
        
        print("=" * 50)
        print("Analysis complete")
        print(f"Verdict: {verdict}")
        print("=" * 50)
        
        return result
        
    except Exception as e:
        print(f"Error in analyze_email: {e}")
        traceback.print_exc()
        return {"error": f"Analysis error: {str(e)}"}