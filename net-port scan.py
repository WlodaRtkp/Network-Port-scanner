import socket
import threading
from queue import Queue
from scapy.all import ARP, Ether, srp

def discover_hosts(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    clients.sort(key=lambda x: socket.inet_aton(x['ip']))

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for i, client in enumerate(clients):
        print(f"{i+1}: {client['ip']:16}    {client['mac']}")
    
    return clients

def portscan(target_ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target_ip, port))
        service_name = get_service_name(port)
        print(f"Port {port}/tcp open - {service_name}")
    except Exception as e:
        pass

def get_service_name(port):
    
    service_names = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
	88: "Kerberos",
	110: "POP3",
	143: "IMAP",
        135: "MSRPC",
        139: "NetBIOS",
        443: "HTTPS",
	445: "SMB",
	514: "Syslog",
	587: "SMTP",
	636: "LDAP",
	902: "VMware ESXi",
	3306: "MySQL",
	5432: "PostgreSQL",
	6514: "Syslog",
        # Add more port-service mappings if needed
    }
    return service_names.get(port, "Unknown")

def main():
    target_ip = input("IP range: ")
    clients = discover_hosts(target_ip)

    targets = input('Enter the host numbers to be scanned separated by commas (e.g., 1,2,3) or "ALL" for all hosts: ')
    if targets.upper() == 'ALL':
        for client in clients:
            print(f"Starting scan on host: {client['ip']}")
            for port in range(1, 9000):
                portscan(client['ip'], port)
    else:
        try:
            target_nums = map(int, targets.split(','))
            for target_num in target_nums:
                if 1 <= target_num <= len(clients):
                    client = clients[target_num - 1]
                    print(f"Starting scan on host: {client['ip']}")
                    for port in range(1, 9000):
                        portscan(client['ip'], port)
                else:
                    print(f"Invalid host number: {target_num}")
        except ValueError:
            print("Invalid input")

if __name__ == "__main__":
    main()

