import nmap
import socket

def is_valid_ip(ip):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def scan_ports(ip, ports, protocol='tcp'):
    """
    Scan specified ports on a given IP address
    
    Args:
        ip (str): Target IP address
        ports (list): List of ports to scan
        protocol (str): Protocol to scan ('tcp' or 'udp')
        
    Returns:
        dict: Scan results including open ports and services
    """
    if not is_valid_ip(ip):
        raise ValueError("Invalid IP address format")
    
    if protocol not in ['tcp', 'udp']:
        raise ValueError("Protocol must be 'tcp' or 'udp'")
    
    nm = nmap.PortScanner()
    port_str = ','.join(map(str, ports))
    
    # Adjust scan type based on protocol
    scan_args = f'-sV -p {port_str} --version-intensity 3'
    if protocol == 'udp':
        scan_args = '-sU ' + scan_args  # Add UDP scan flag
    
    try:
        # Run the scan with service version detection
        nm.scan(ip, arguments=scan_args)
        
        # Get scan results
        scan_results = {
            'ip': ip,
            'hostname': nm[ip].hostname() or ip,
            'state': nm[ip].state(),
            'protocols': {}
        }
        
        # Get protocol information
        for proto in nm[ip].all_protocols():
            scan_results['protocols'][proto] = {}
            ports = nm[ip][proto].keys()
            
            for port in ports:
                port_info = nm[ip][proto][port]
                scan_results['protocols'][proto][port] = {
                    'state': port_info['state'],
                    'service': port_info['name'],
                    'version': port_info.get('version', 'unknown'),
                    'product': port_info.get('product', ''),
                    'extrainfo': port_info.get('extrainfo', '')
                }
        
        return scan_results
        
    except Exception as e:
        return {
            'error': str(e),
            'ip': ip,
            'hostname': ip,
            'state': 'error',
            'protocols': {}
        }
