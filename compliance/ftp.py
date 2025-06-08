def check_ftp_compliance(scan_results):
    """
    Check FTP compliance based on scan results
    
    Args:
        scan_results (dict): Results from NMap scan
        
    Returns:
        list: List of compliance check results
    """
    results = []
    ftp_services = {}
    
    # Extract FTP service information
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if 'ftp' in info.get('service', '').lower() and info.get('state') == 'open':
                ftp_services[f"{port}/{proto}"] = info
    
    # Check 1: FTP Service Exposure
    results.append({
        'parameter': 'FTP Service Exposure',
        'status': 'Non-Compliant' if ftp_services else 'Compliant',
        'threat_level': 'Info',
        'details': f"FTP services found: {', '.join(ftp_services.keys()) if ftp_services else 'No FTP services found'}"
    })
    
    # If no FTP services found, return early
    if not ftp_services:
        return results
    
    # Check 2: FTP Version Visibility
    version_exposed = []
    for port_proto, info in ftp_services.items():
        version = info.get('version', '')
        if version and version != 'unknown':
            version_exposed.append(f"{port_proto}: {version}")
    
    results.append({
        'parameter': 'FTP Version Visibility',
        'status': 'Compliant' if not version_exposed else 'Non-Compliant',
        'threat_level': 'Medium',
        'details': '\n'.join(version_exposed) if version_exposed \
                 else 'No version information exposed (Compliant)'
    })
    
    # Check 3: Secure Channel Usage
    secure_ports = ['990/tcp', '21/tcp']  # FTPS and SFTP common ports
    secure_services = []
    
    for port_proto in ftp_services:
        if port_proto in secure_ports:
            secure_services.append(port_proto)
    
    results.append({
        'parameter': 'Secure Channel Usage',
        'status': 'Compliant' if secure_services else 'Non-Compliant',
        'threat_level': 'Low',
        'details': f"Using secure channels: {', '.join(secure_services)}" if secure_services \
                 else 'FTP service not using secure channels (FTPS/SFTP)'
    })
    
    # Note: Anonymous FTP upload check would require specific NSE script (ftp-anon.nse)
    # We'll include it as a note since it can't be determined from basic scan
    results.append({
        'parameter': 'Anonymous FTP Upload',
        'status': 'Manual Check Required',
        'threat_level': 'Medium',
        'details': 'Use NSE script: nmap --script=ftp-anon -p 21 <target> to check for anonymous uploads.'
    })
    
    return results
