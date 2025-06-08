def check_utm_compliance(scan_results):
    """
    Check UTM compliance based on scan results
    
    Args:
        scan_results (dict): Results from NMap scan
        
    Returns:
        list: List of compliance check results
    """
    results = []
    
    # Check 1: List Open Ports
    open_ports = []
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if info.get('state') == 'open':
                open_ports.append(f"{port}/{proto}")
    
    results.append({
        'parameter': 'List Open Ports',
        'status': 'Compliant' if not open_ports else 'Non-Compliant',
        'threat_level': 'Medium',
        'details': f"Open ports: {', '.join(open_ports) if open_ports else 'No open ports found'}"
    })
    
    # Check 2: Management Port Exposure
    mgmt_ports = ['22', '23', '80', '443', '8080', '8443']
    exposed_mgmt = []
    
    for port_proto in open_ports:
        port = port_proto.split('/')[0]
        if port in mgmt_ports:
            exposed_mgmt.append(port_proto)
    
    results.append({
        'parameter': 'Management Port Exposure',
        'status': 'Non-Compliant' if exposed_mgmt else 'Compliant',
        'threat_level': 'High',
        'details': f"Exposed management ports: {', '.join(exposed_mgmt) if exposed_mgmt else 'No management ports exposed'}"
    })
    
    # Check 3: Web Login Exposure
    web_ports = ['80', '443', '8080', '8443']
    web_services = []
    
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if info.get('state') == 'open' and port in web_ports and 'http' in info.get('service', '').lower():
                web_services.append(f"{port}/{proto} ({info.get('product', '')} {info.get('version', '')})")
    
    results.append({
        'parameter': 'Web Login Exposure',
        'status': 'Non-Compliant' if web_services else 'Compliant',
        'threat_level': 'High',
        'details': f"Web services detected: {', '.join(web_services) if web_services else 'No web services detected'}"
    })
    
    # Check 4: Services Running
    services = []
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if info.get('state') == 'open':
                services.append(f"{port}/{proto}: {info.get('service', '')} {info.get('version', '')}")
    
    results.append({
        'parameter': 'Services Running',
        'status': 'Info',
        'threat_level': 'Info',
        'details': '\n'.join(services) if services else 'No services detected'
    })
    
    # Check 5: Version Information Visibility
    version_exposure = False
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if info.get('state') == 'open' and info.get('version') not in ['', 'unknown']:
                version_exposure = True
                break
    
    results.append({
        'parameter': 'Version Information Visible',
        'status': 'Non-Compliant' if version_exposure else 'Compliant',
        'threat_level': 'Medium',
        'details': 'Version information is exposed' if version_exposure else 'No version information exposed'
    })
    
    return results
