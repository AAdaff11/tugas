import nmap
import socket
from datetime import datetime
import subprocess
import platform
import re

def get_network_range():
    """Auto-detect network range without user input"""
    try:
        # Method 1: Socket connection (most reliable)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            network_prefix = '.'.join(local_ip.split('.')[:3])
            print(f"🔍 Auto-detected network: {network_prefix}.0/24")
            return f"{network_prefix}.0/24"
    except Exception as e:
        print(f"⚠️  Socket detection failed: {e}")
    
    try:
        # Method 2: IP config parsing (fallback)
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
            matches = re.findall(r'IPv4[^:]*:\s*(\d+\.\d+\.\d+)\.\d+', result)
            if matches:
                network_prefix = matches[0]
                print(f"🔍 Auto-detected network (ipconfig): {network_prefix}.0/24")
                return f"{network_prefix}.0/24"
        else:  # Linux/Mac
            result = subprocess.check_output("ifconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
            matches = re.findall(r'inet (\d+\.\d+\.\d+)\.\d+', result)
            for match in matches:
                if not match.startswith('127.'):  # Skip localhost
                    network_prefix = match
                    print(f"🔍 Auto-detected network (ifconfig): {network_prefix}.0/24")
                    return f"{network_prefix}.0/24"
    except Exception as e:
        print(f"⚠️  IP config detection failed: {e}")
    
    # Final fallback
    fallback_network = "192.168.1.0/24"
    print(f"⚠️  Using fallback network: {fallback_network}")
    return fallback_network

def scan_devices(ip_range=None):
    """Scan devices on network using nmap"""
    
    # Auto-detect network if no range provided
    if ip_range is None:
        ip_range = get_network_range()
    
    print(f"🚀 Starting nmap scan on: {ip_range}")
    print(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip_range, arguments='-sn')  # Ping scan
        
        active_devices = []
        for host in scanner.all_hosts():
            active_devices.append({
                'ip': host,
                'mac': scanner[host].get('addresses', {}).get('mac', 'Unknown'),
                'hostname': scanner[host].hostname() or 'Unknown',
                'status': 'up'
            })
        
        print(f"✅ Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return active_devices
        
    except nmap.PortScannerError as e:
        print(f"❌ Nmap error: {e}")
        return []
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return []

def print_results(devices):
    """Print scan results in formatted way"""
    print(f"\n📊 SCAN RESULTS:")
    print("=" * 60)
    print(f"{'No.':<4} {'IP Address':<15} {'MAC Address':<18} {'Hostname'}")
    print("-" * 60)
    
    for i, device in enumerate(devices, 1):
        mac = device['mac'] if device['mac'] != 'Unknown' else 'N/A'
        hostname = device['hostname'] if device['hostname'] != 'Unknown' else 'N/A'
        print(f"{i:<4} {device['ip']:<15} {mac:<18} {hostname}")
    
    print("=" * 60)
    print(f"🎯 Total devices found: {len(devices)}")

# Main execution
import sys

def main():
    if len(sys.argv) > 1:
        # Jika ada argument, gunakan sebagai network range
        ip_range = sys.argv[1]
        print(f"🎯 Using manual network: {ip_range}")
        devices = scan_devices(ip_range)
    else:
        # Auto-detect
        devices = scan_devices()
    
    print_results(devices)

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    print("🛰️  Network Device Scanner")
    print("🔧 Auto-detecting network range...")
    
    # Scan with auto-detection
    devices = scan_devices()  # No need to pass IP range
    
    if devices:
        print_results(devices)
    else:
        print("❌ No devices found or scan failed!")
        
    print("\n💡 Tips: If scan shows wrong network, manually specify:")
    print("       devices = scan_devices('192.168.0.0/24')")