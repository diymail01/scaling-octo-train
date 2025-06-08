def check_ssh_compliance(scan_results):
    """
    Check SSH compliance based on scan results
    
    Args:
        scan_results (dict): Results from NMap scan
        
    Returns:
        list: List of compliance check results
    """
    results = []
    ssh_services = {}
    
    # Extract SSH service information
    for proto, ports in scan_results.get('protocols', {}).items():
        for port, info in ports.items():
            if 'ssh' in info.get('service', '').lower() and info.get('state') == 'open':
                ssh_services[f"{port}/{proto}"] = info
    
    # Check 1: SSH Service Exposure
    results.append({
        'parameter': 'SSH Service Exposure',
        'status': 'Non-Compliant' if ssh_services else 'Compliant',
        'threat_level': 'High',
        'details': f"SSH services found: {', '.join(ssh_services.keys()) if ssh_services else 'No SSH services found'}"
    })
    
    # If no SSH services found, return early
    if not ssh_services:
        return results
    
    # Check 2: SSH Version Information
    version_exposed = []
    for port_proto, info in ssh_services.items():
        version = info.get('version', '')
        if version and version != 'unknown':
            version_exposed.append(f"{port_proto}: {version}")
    
    results.append({
        'parameter': 'SSH Version Exposure',
        'status': 'Non-Compliant' if version_exposed else 'Compliant',
        'threat_level': 'Medium',
        'details': '\n'.join(version_exposed) if version_exposed else 'No version information exposed'
    })
    
    # Check 3: Default SSH Port Usage
    default_ssh_ports = ['22/tcp', '22/udp']
    using_default = []
    
    for port_proto in ssh_services:
        if port_proto in default_ssh_ports:
            using_default.append(port_proto)
    
    results.append({
        'parameter': 'Default SSH Port Usage',
        'status': 'Non-Compliant' if using_default else 'Compliant',
        'threat_level': 'Medium',
        'details': f"Using default SSH ports: {', '.join(using_default)}" if using_default \
                 else 'No default SSH ports in use'
    })
    
    # Check 4: SSH Protocol Version
    protocol_v1 = []
    for port_proto, info in ssh_services.items():
        version = info.get('version', '').lower()
        if 'openssh' in version and ('1.' in version or 'protocol 1' in version):
            protocol_v1.append(port_proto)
    
    results.append({
        'parameter': 'SSH Protocol Version 1',
        'status': 'Non-Compliant' if protocol_v1 else 'Compliant',
        'threat_level': 'High',
        'details': f"SSHv1 detected on: {', '.join(protocol_v1)}" if protocol_v1 \
                 else 'No SSHv1 services detected'
    })
    
    # Check 5: SSH Weak Algorithms
    weak_algorithms = []
    for port_proto, info in ssh_services.items():
        version = info.get('version', '').lower()
        # This is a simple check; in a real-world scenario, you'd want to use a tool like ssh-audit
        if 'weak' in version or 'vulnerable' in version:
            weak_algorithms.append(f"{port_proto}: {version}")
    
    results.append({
        'parameter': 'Weak SSH Algorithms',
        'status': 'Non-Compliant' if weak_algorithms else 'Compliant',
        'threat_level': 'High' if weak_algorithms else 'Info',
        'details': '\n'.join(weak_algorithms) if weak_algorithms \
                 else 'No obviously weak algorithms detected (manual verification recommended)'
    })
    
    return results
