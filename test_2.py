import socket
import subprocess
import platform
import re
from datetime import datetime

import requests
from collections import Counter
import threading
import concurrent.futures

def get_network_range():
    """Auto-detect network range"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            network_prefix = '.'.join(local_ip.split('.')[:3])
            print(f"🔍 Auto-detected network: {network_prefix}.0/24")
            return network_prefix
    except Exception as e:
        print(f"⚠️ Socket detection failed: {e}")
        return "192.168.18"

def get_arp_table():
    """Get MAC addresses from ARP table"""
    try:
        result = subprocess.check_output("arp -a", shell=True, text=True)
        arp_Perangkats = {}
        
        for line in result.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})', line)
            if match:
                ip, mac = match.groups()
                arp_Perangkats[ip] = mac
        return arp_Perangkats
    except Exception as e:
        print(f"⚠️ ARP table error: {e}")
        return {}

def get_vendor_from_mac(mac_address):
    """Convert MAC address to vendor name"""
    if mac_address == 'N/A' or not mac_address:
        return 'N/A'
    
    try:
        # Online OUI lookup
        try:
            response = requests.get(f'https://api.macvendors.com/{mac_address}', timeout=1)
            if response.status_code == 200:
                return response.text
        except:
            pass
        
        # Local OUI database dengan nama lebih user-friendly
        oui_database = {
            '183D5E': 'Huawei', '001C10': 'Cisco', '0021CC': 'Samsung',
            '0022CF': 'LG', '0023D4': 'Sony', '0024E8': 'Huawei', 
            '0025CF': 'Xiaomi', '0026AB': 'Apple', '002710': 'D-Link',
            '002764': 'TP-Link', '001D0F': 'Netgear', '001E8C': 'Intel',
            '001F3B': 'Asus', 'FCFC48': 'Apple', 'A4C361': 'Huawei',
            'B888E3': 'Apple', 'C05627': 'Belkin', 'D85DFB': 'Samsung',
            'E4CE02': 'Huawei', 'F0272D': 'Google', 'F832E4': 'ASUS',
            'FCD848': 'Dell', 'A01290': 'Huawei', 'B0754D': 'Samsung',
            'C81EE7': 'Apple', '080028': 'Apple', '000C29': 'VMware',
        }
        
        mac_clean = mac_address.replace(':', '').replace('-', '').upper()
        oui = mac_clean[:6]
        return oui_database.get(oui, 'Unknown')
    except:
        return 'N/A'

def get_Perangkat_hostname(ip):
    """Get hostname dengan multiple methods"""
    hostnames = []
    
    # Method 1: Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            hostnames.append(hostname)
    except:
        pass
    
    # Method 2: NetBIOS (Windows)
    if platform.system() == "Windows":
        try:
            result = subprocess.check_output(f"nbtstat -A {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
            lines = result.split('\n')
            for line in lines:
                if '<00>' in line and 'PerangkatE' in line and not 'WORKGROUP' in line:
                    netbios_name = line.split()[0].strip()
                    if netbios_name:
                        hostnames.append(netbios_name)
                        break
        except:
            pass
    
    # Method 3: SMB Client (jika ada)
    try:
        result = subprocess.check_output(f"net view \\\\{ip}", shell=True, text=True, stderr=subprocess.DEVNULL, timeout=2)
        if "System error" not in result:
            for line in result.split('\n'):
                if "\\\\" in line:
                    smb_name = line.split('\\\\')[-1].strip()
                    if smb_name:
                        hostnames.append(smb_name)
    except:
        pass
    
    return hostnames[0] if hostnames else 'N/A'

def get_Perangkat_type(mac, vendor, hostname):
    """Determine Perangkat type based on MAC, vendor, and hostname"""
    if vendor == 'N/A' and mac == 'N/A':
        return 'Unknown'
    
    vendor_lower = vendor.lower()
    hostname_lower = hostname.lower() if hostname != 'N/A' else ''
    
    # Smartphone detection
    if any(keyword in vendor_lower for keyword in ['samsung', 'xiaomi', 'huawei', 'apple', 'google', 'oneplus', 'oppo', 'vivo']):
        if 'router' not in hostname_lower and 'ap' not in hostname_lower:
            return 'Smartphone'
    
    # Computer detection
    if any(keyword in hostname_lower for keyword in ['desktop', 'pc', 'laptop', 'notebook', 'computer']):
        return 'Computer'
    
    if any(keyword in vendor_lower for keyword in ['microsoft', 'dell', 'hp', 'lenovo', 'asus', 'acer']):
        return 'Computer'
    
    # Router/Network equipment
    if any(keyword in vendor_lower for keyword in ['cisco', 'tplink', 'd-link', 'netgear', 'linksys', 'huawei', 'zte']):
        return 'Router/Network Perangkat'
    
    # IoT Perangkats
    if any(keyword in hostname_lower for keyword in ['iot', 'smart', 'camera', 'printer']):
        return 'IoT Perangkat'
    
    return 'Network Perangkat'

def ping_ip(ip):
    """Ping single IP address"""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.call(
            ["ping", param, "1", "-w", "200", ip],  # Reduced timeout to 200ms
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return ip if result == 0 else None
    except:
        return None

def fast_ping_scan(network_prefix):
    """Fast parallel ping scan"""
    print(f"🚀 Fast scanning {network_prefix}.1-254...")
    
    active_ips = []
    
    # Use thread pool for parallel pinging
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for i in range(1, 255):
            ip = f"{network_prefix}.{i}"
            futures.append(executor.submit(ping_ip, ip))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                active_ips.append(result)
                print(f"✅ IP ditemukan: {result}")
    
    return active_ips

def scan_Perangkats_fast(network_prefix):
    """Fast scan dengan parallel processing"""
    # Step 1: Fast ping scan
    active_ips = fast_ping_scan(network_prefix)
    
    # Step 2: Get ARP table once
    arp_table = get_arp_table()
    
    # Step 3: Get details for active Perangkats
    Perangkats = []
    print(f"\n🔍 Mencari detail info perangkat...")
    
    for ip in active_ips:
        mac = arp_table.get(ip, 'N/A')
        vendor = get_vendor_from_mac(mac)
        hostname = get_Perangkat_hostname(ip)
        Perangkat_type = get_Perangkat_type(mac, vendor, hostname)
        
        Perangkats.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'type': Perangkat_type
        })
    
    return Perangkats

def print_detailed_results(Perangkats):
    """Print results dengan Perangkat type"""
    print(f"\n📊 DETAILED SCAN RESULTS:")
    print("=" * 120)
    print(f"{'No.':<4} {'IP Address':<15} {'MAC Address':<18} {'Hostname':<20} {'Vendor':<20} {'Perangkat Type'}")
    print("-" * 120)
    
    for i, Perangkat in enumerate(Perangkats, 1):
        mac = Perangkat['mac'] if Perangkat['mac'] != 'N/A' else 'N/A'
        hostname = Perangkat['hostname'] if Perangkat['hostname'] != 'N/A' else 'N/A'
        vendor = Perangkat['vendor'] if Perangkat['vendor'] != 'N/A' else 'N/A'
        Perangkat_type = Perangkat['type']
        
        print(f"{i:<4} {Perangkat['ip']:<15} {mac:<18} {hostname:<20} {vendor:<20} {Perangkat_type}")
    
    print("=" * 120)
    print(f"🎯 Total perangkat ditemukan: {len(Perangkats)}")

def print_enhanced_statistics(Perangkats):
    """Print enhanced statistics"""
    vendors = [d['vendor'] for d in Perangkats if d['vendor'] != 'N/A']
    Perangkat_types = [d['type'] for d in Perangkats]
    
    if vendors:
        vendor_count = Counter(vendors)
        type_count = Counter(Perangkat_types)
        
        print(f"\n📈 ENHANCED STATISTICS:")
        print("-" * 40)
        print("🏢 VENDORS:")
        for vendor, count in vendor_count.most_common():
            print(f"   {vendor}: {count} Perangkat")
        
        print(f"\n📱 Perangkat TYPES:")
        for Perangkat_type, count in type_count.most_common():
            print(f"   {Perangkat_type}: {count} Perangkat")
        
        # Summary
        print(f"\n📋 Laporan:")
        print(f"   Total Perangkats: {len(Perangkats)}")
        print(f"   Perangkats with MAC: {len([d for d in Perangkats if d['mac'] != 'N/A'])}")
        print(f"   Perangkats with hostname: {len([d for d in Perangkats if d['hostname'] != 'N/A'])}")
        print(f"   Perangkate vendors: {len(vendor_count)}")
        print(f"   Perangkat categories: {len(type_count)}")

if __name__ == "__main__":
    print("🛰️  Memulai Scan ")
    print("=" * 55)
    
    network_prefix = get_network_range()
    print(f"⏰ Waktu start scan : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    Perangkats = scan_Perangkats_fast(network_prefix)
    
    print(f"✅ Scan selesai saat: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if Perangkats:
        print_detailed_results(Perangkats)
        print_enhanced_statistics(Perangkats)
        
        # Save enhanced results
        try:
            with open('enhanced_network_scan.txt', 'w') as f:
                f.write("ENHANCED NETWORK SCAN RESULTS\n")
                f.write("=" * 50 + "\n")
                f.write(f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Network: {network_prefix}.0/24\n")
                f.write(f"Total Perangkats: {len(Perangkats)}\n\n")
                
                for Perangkat in Perangkats:
                    f.write(f"IP: {Perangkat['ip']:<15} | MAC: {Perangkat['mac']:<18} | Hostname: {Perangkat['hostname']:<20} | Vendor: {Perangkat['vendor']:<20} | Type: {Perangkat['type']}\n")
            
            print(f"\n💾 Hasil Bisa Dicek di: enhanced_network_scan.txt")
        except Exception as e:
            print(f"⚠️ Could not save to file: {e}")
            
    else:
        print("❌ No Perangkats found!")