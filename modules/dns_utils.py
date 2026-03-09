import dns.resolver

def query_txt(domain):
    """Fetch TXT records for a domain, return list of strings."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [str(rdata).strip('"') for rdata in answers]
    except Exception:
        return []