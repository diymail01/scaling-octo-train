def check_dns_compliance(scan_results):
    """
    Check DNS compliance based on scan results
    
    Args:
        scan_results (dict): Results from NMap scan
        
    Returns:
        list: List of compliance check results
    """
    results = []
    dns_services = {}
    
    # Extract DNS service information
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if 'domain' in info.get('service', '').lower() and info.get('state') == 'open':
                dns_services[f"{port}/{proto}"] = info
    
    # Check 1: DNS Service Exposure
    results.append({
        'parameter': 'DNS Service Exposure',
        'status': 'Non-Compliant' if dns_services else 'Compliant',
        'threat_level': 'Info',
        'details': f"DNS services found: {', '.join(dns_services.keys()) if dns_services else 'No DNS services found'}"
    })
    
    # If no DNS services found, return early
    if not dns_services:
        return results
    
    # Check 2: Non-Standard Ports
    standard_ports = ['53/udp', '53/tcp', '853/tcp']  # Standard DNS and DNS-over-TLS
    non_standard_ports = []
    
    for port_proto in dns_services:
        if port_proto not in standard_ports:
            non_standard_ports.append(port_proto)
    
    results.append({
        'parameter': 'Non-Standard DNS Ports',
        'status': 'Compliant' if not non_standard_ports else 'Non-Compliant',
        'threat_level': 'Info',
        'details': f"Non-standard DNS ports: {', '.join(non_standard_ports)}" if non_standard_ports \
                 else 'Only standard DNS ports in use (53/udp, 53/tcp, 853/tcp)'
    })
    
    # Check 3: DNS Version Visibility
    version_exposed = []
    for port_proto, info in dns_services.items():
        version = info.get('version', '')
        if version and version != 'unknown':
            version_exposed.append(f"{port_proto}: {version}")
    
    results.append({
        'parameter': 'DNS Version Visibility',
        'status': 'Compliant' if not version_exposed else 'Non-Compliant',
        'threat_level': 'Medium',
        'details': '\n'.join(version_exposed) if version_exposed \
                 else 'No version information exposed (Compliant)'
    })
    
    # Note: Open recursion check would require specific DNS queries
    # We'll include it as a note since it can't be determined from basic scan
    results.append({
        'parameter': 'Open Recursion Check',
        'status': 'Manual Check Required',
        'threat_level': 'High',
        'details': 'Check for open recursion using: \n' \
                 '1. dig +short test.openresolver.com TXT @<dns-server-ip>\n' \
                 '2. nmap -sU -p 53 --script dns-recursion <dns-server-ip>'
    })
    
    return results
