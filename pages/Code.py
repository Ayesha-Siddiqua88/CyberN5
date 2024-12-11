import streamlit as st
import subprocess
import json
import platform
from streamlit_option_menu import option_menu


def get_microsoft_updates():
    command = 'powershell -Command "Get-WmiObject -Class Win32_QuickFixEngineering"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_amsi_providers():
    command = [
        "powershell",
        "-Command",
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\AMSI' | Select-Object -Property *"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_arp_and_adapter_info():
    command = 'powershell -Command "Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_os_info():
    return {
        "System": platform.system(),
        "Node": platform.node(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
    }

def get_tcp_udp_connections():
    command = 'powershell -Command "Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_dns_cache_entries():
    command = 'powershell -Command "Get-DnsClientCache"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_firewall_rules():
    command = ["powershell", "-Command", "Get-NetFirewallRule"]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_local_users():
    command = 'powershell -Command "Get-LocalUser | Select-Object Name, Enabled"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_secure_boot_configuration():
    command = 'powershell -Command "Get-WmiObject -Class Win32_BootConfiguration"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_registered_antivirus():
    command = ["powershell", "-Command", "Get-WmiObject -Namespace 'root\\SecurityCenter2' -Class AntiVirusProduct"]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

def get_uac_system_policies():
    command = 'powershell -Command "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

# Streamlit UI
def main():
    st.set_page_config(page_title="System and Network Info", layout="wide", initial_sidebar_state="expanded")

    st.markdown(
        """
        <style>
        body {
            background-color: #f5f5f5;
        }
        .stButton>button {
            color: white;
            background-color: #4CAF50;
            border: none;
            border-radius: 8px;
            padding: 10px 20px;
            font-size: 16px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Sidebar
    with st.sidebar:
        st.markdown(
        """
        <style>
        .option-menu-container .nav-item {
            color:#f7d7b6;
        }
        .option-menu-container .nav-item:hover {
            background-color:#fbc185;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
        tab = option_menu(menu_title=None,
                        options=['📖 Introduction', '🔍 Scanning'],
                        menu_icon='hospital-fill',
                        icons=['scan',  'scan'],
                        default_index=0)

    if tab == "📖 Introduction":
        st.title("🔧 System and Network Info Scanner")
        st.write("This app retrieves detailed system and network information. Use the navigation bar to scan specific parameters.")

    elif tab == "🔍 Scanning":
        st.title("Scanning Options")

        # Checkboxes for scan parameters
        parameters = {
            "Microsoft Updates": get_microsoft_updates,
            "AMSI Providers": get_amsi_providers,
            "ARP and Adapter Info": get_arp_and_adapter_info,
            "OS Info": lambda: json.dumps(get_os_info(), indent=2),
            "TCP/UDP Connections": get_tcp_udp_connections,
            "DNS Cache Entries": get_dns_cache_entries,
            "Firewall Rules": get_firewall_rules,
            "Local Users": get_local_users,
            "Secure Boot Configuration": get_secure_boot_configuration,
            "Registered Antivirus": get_registered_antivirus,
            "UAC System Policies": get_uac_system_policies,
        }

        selected_parameters = {key: st.checkbox(key) for key in parameters.keys()}

        if st.button("Scan the Parameters"):
            st.info("Scanning selected parameters......Please wait.")
            results = {key: func() for key, func in parameters.items() if selected_parameters[key]}

            # Display the results
            st.subheader("Scan Results")
            for key, value in results.items():
                st.write(f"### {key}")
                st.code(value)

main()