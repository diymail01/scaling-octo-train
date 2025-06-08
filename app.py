import streamlit as st

# Page configuration must be the first Streamlit command
st.set_page_config(
    page_title="Perimeter Network Compliance Audit Tool",
    page_icon="🔒",
    layout="wide"
)

import os
import time
from scans.nmap_scan import scan_ports
from reports.pdf_report import generate_pdf_report
from auth import verify_user, create_user, list_users

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.page = 'dashboard'

def login_page():
    """Display login form and handle authentication"""
    st.title("🔒 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            user = verify_user(username, password)
            if user:
                st.session_state.authenticated = True
                st.session_state.username = user['username']
                st.session_state.role = user['role']
                st.success(f"Welcome, {user['username']}!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid username or password")
    
    # Add a link to the user management page for admin
    if st.button("User Management"):
        st.session_state.page = "user_management"
        st.rerun()

def user_management_page():
    """Page for managing users (admin only)"""
    if not st.session_state.authenticated or st.session_state.role != 'scanner':
        st.warning("You don't have permission to access this page.")
        return
    
    st.title("👥 User Management")
    
    # Add new user form
    with st.expander("Add New User", expanded=True):
        with st.form("add_user_form"):
            st.subheader("Add New User")
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                new_username = st.text_input("Username", key="new_username")
            with col2:
                new_password = st.text_input("Password", type="password", key="new_password")
            with col3:
                new_role = st.selectbox("Role", ["scanner", "viewer"], 
                                     format_func=lambda x: "Scanner" if x == "scanner" else "Viewer")
            
            submit = st.form_submit_button("Add User")
            
            if submit:
                if not new_username or not new_password:
                    st.error("Username and password are required")
                elif create_user(new_username, new_password, new_role):
                    st.success(f"User '{new_username}' created successfully!")
                    # Clear the form
                    st.rerun()
                else:
                    st.error("Failed to create user. Username may already exist.")
    
    # List existing users
    st.subheader("Existing Users")
    st.info("Note: For security, only usernames and roles are shown.")
    
    # Fetch users from database
    users = list_users()
    
    if not users:
        st.warning("No users found in the database.")
    else:
        # Display users in a table
        user_data = [[user['username'], 'Scanner' if user['role'] == 'scanner' else 'Viewer'] 
                    for user in users]
        
        # Add headers
        headers = ["Username", "Role"]
        user_data.insert(0, headers)
        
        # Display table
        st.table(user_data)
    
    if st.button("🔄 Refresh User List"):
        st.rerun()
        
    if st.button("⬅️ Back to Dashboard"):
        st.session_state.page = "dashboard"
        st.rerun()



def main():
    # Check authentication
    if not st.session_state.authenticated:
        login_page()
        return
    
    # Set default page if not set
    if 'page' not in st.session_state:
        st.session_state.page = "dashboard"
    
    # Sidebar - User info and logout
    with st.sidebar:
        st.title(f"Welcome, {st.session_state.username}")
        st.caption(f"Role: {st.session_state.role.capitalize()}")
        
        if st.button("🔒 Logout"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.role = None
            st.session_state.page = "dashboard"
            st.rerun()
        
        st.title("Navigation")
        
        # Navigation options based on role
        nav_options = ["Dashboard"]
        
        if st.session_state.role == 'scanner':
            nav_options.extend([
                "UTM Compliance", 
                "SSH Compliance",
                "FTP Compliance",
                "DNS Compliance"
            ])
        
        nav_options.append("View Reports")
        
        if st.session_state.role == 'scanner':
            nav_options.append("User Management")
        
        page = st.radio("Go to", nav_options, key="nav_radio")
        
        # Update session state based on selection
        if page != st.session_state.get('current_page'):
            st.session_state.page = page.lower().replace(' ', '_')
            st.session_state.current_page = page
            st.rerun()
    
    # Handle page routing
    if st.session_state.page == "dashboard":
        show_home()
    elif st.session_state.page == "user_management":
        user_management_page()
    elif st.session_state.page == "view_reports":
        show_reports_page()
    elif st.session_state.page in ["utm_compliance", "ssh_compliance", "ftp_compliance", "dns_compliance"]:
        if st.session_state.role != 'scanner':
            st.warning("You don't have permission to run scans.")
            st.session_state.page = "dashboard"
            st.rerun()
        
        category_map = {
            "utm_compliance": ("UTM", [80, 443, 22, 8080], None),
            "ssh_compliance": ("SSH", [22], None),
            "ftp_compliance": ("FTP", [20, 21, 990], None),
            "dns_compliance": ("DNS", [53, 853], [53])
        }
        
        category, ports, udp_ports = category_map[st.session_state.page]
        show_scan_page(category, ports, udp_ports)
    
    # This function should not be reached as all routes are handled above

def show_home():
    st.markdown("""
    ## Welcome to Perimeter Network Compliance Audit Tool
    
    This tool helps you audit the compliance of your perimeter network devices.
    
    ### How to use:
    1. Select a compliance category from the sidebar
    2. Enter the target IP address
    3. Click 'Run Scan' to start the compliance check
    4. View results and download the PDF report
    
    ### Supported Categories:
    - UTM Compliance
    - SSH Compliance
    
    *More categories coming soon!*
    """)

def show_scan_page(category, ports, udp_ports=None):
    st.header(f"{category} Compliance Check")
    
    # IP input
    ip_address = st.text_input("Enter IP Address:", placeholder="192.168.1.1")
    
    # Convert ports to integers and handle UDP ports
    tcp_ports = [int(p) for p in ports] if ports else []
    udp_ports = [int(p) for p in udp_ports] if udp_ports else []
    
    if st.button("Run Scan"):
        if not ip_address:
            st.error("Please enter a valid IP address")
            return
            
        with st.spinner(f"Scanning {ip_address} for {category} compliance..."):
            # Run Nmap scan for TCP ports
            tcp_scan_results = scan_ports(ip_address, tcp_ports, 'tcp') if tcp_ports else {}
            
            # Run Nmap scan for UDP ports if specified
            udp_scan_results = scan_ports(ip_address, udp_ports, 'udp') if udp_ports else {}
            
            # Merge scan results
            scan_results = {
                'ip': ip_address,
                'hostname': tcp_scan_results.get('hostname', ip_address) or udp_scan_results.get('hostname', ip_address),
                'state': tcp_scan_results.get('state', 'down') if tcp_scan_results else udp_scan_results.get('state', 'down'),
                'protocols': {}
            }
            
            # Merge TCP and UDP protocols
            for proto in ['tcp', 'udp']:
                if proto in tcp_scan_results.get('protocols', {}):
                    scan_results['protocols'][proto] = tcp_scan_results['protocols'][proto]
                if proto in udp_scan_results.get('protocols', {}):
                    if proto not in scan_results['protocols']:
                        scan_results['protocols'][proto] = {}
                    scan_results['protocols'][proto].update(udp_scan_results['protocols'][proto])
            
            # Get compliance results based on category
            if category == "UTM":
                from compliance.utm import check_utm_compliance
                compliance_results = check_utm_compliance(scan_results)
            elif category == "SSH":
                from compliance.ssh import check_ssh_compliance
                compliance_results = check_ssh_compliance(scan_results)
            elif category == "FTP":
                from compliance.ftp import check_ftp_compliance
                compliance_results = check_ftp_compliance(scan_results)
            elif category == "DNS":
                from compliance.dns import check_dns_compliance
                compliance_results = check_dns_compliance(scan_results)
            
            # Display results
            display_results(compliance_results, category, ip_address)

def display_results(compliance_results, category, ip_address):
    st.subheader("Scan Results")
    
    # Create a DataFrame for better display
    import pandas as pd
    df = pd.DataFrame(compliance_results)
    
    # Display the table
    st.dataframe(
        df,
        column_config={
            "status": st.column_config.TextColumn("Status", width="small"),
            "threat_level": st.column_config.TextColumn("Threat Level", width="small")
        },
        hide_index=True,
        use_container_width=True
    )
    
    # Generate and download PDF
    pdf_path = generate_pdf_report(df, category, ip_address)
    
    with open(pdf_path, "rb") as f:
        st.download_button(
            label="Download PDF Report",
            data=f,
            file_name=f"{category}_Compliance_{ip_address}.pdf",
            mime="application/pdf"
        )
    
    # Clean up
    os.remove(pdf_path)

def show_reports_page():
    """Display the reports page"""
    st.title("📊 Reports")
    st.info("Report viewing functionality will be implemented here.")
    
    # Placeholder for report listing
    st.subheader("Available Reports")
    
    # Look for existing reports
    report_dir = "reports"
    if os.path.exists(report_dir):
        reports = [f for f in os.listdir(report_dir) if f.endswith('.pdf')]
        if reports:
            for report in reports:
                st.write(f"• {report}")
        else:
            st.write("No reports available yet.")
    else:
        st.write("No reports directory found.")
    
    if st.button("Back to Dashboard"):
        st.session_state.page = "dashboard"
        st.rerun()

if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("reports", exist_ok=True)
    os.makedirs("scans", exist_ok=True)
    os.makedirs("compliance", exist_ok=True)
    
    # Initialize the app
    if not st.session_state.authenticated:
        login_page()
    else:
        main()