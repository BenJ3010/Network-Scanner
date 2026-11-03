import nmap
import socket
import ipaddress

def detect_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return str(ipaddress.ip_network(f'{ip}/24', strict=False))

def run_scan(targets, arguments='-F -sU -sS -T4 -Pn -sV'):
    nm = nmap.PortScanner()
    nm.scan(targets, arguments=arguments)
    return nm

def extract_results(nm):
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                results.append({
                    'host': host,
                    'protocol': proto,
                    'port': port,
                    'state': info['state'],
                    'name': info['name'],
                    'product': info['product'],
                    'version': info['version']
                })
    return results

def discover_hosts(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            hosts.append({
                'ip': host,
                'hostname': nm[host].hostname(),
                'vendor': next(iter(nm[host].get('vendor', {}).values()), ''),
            })
    return hosts

def choose_target(hosts):
    for i, h in enumerate(hosts, start=1):
        print(f"{i}. {h['ip']}  {h['hostname']}  {h['vendor']}")
    while True:
        choice = input("Pick a number: ").strip()
        try:
            number = int(choice)
        except ValueError:
            print("Please enter a number.")
            continue
        if 1 <= number <= len(hosts):
            return hosts[number - 1]['ip']
        print(f"Pick a number between 1 and {len(hosts)}.")

def main():
    try:
        network = detect_network()
    except OSError:
        network = input("Could not detect network. Enter CIDR (e.g. 192.168.0.0/24): ").strip()  # NEW
    print(f"Detected network: {network}")
    print(f"Discovering hosts on {network}...")
    hosts = discover_hosts(network)
    if not hosts:
        print("No hosts found.")
        return
    temp = choose_target(hosts)
    targets = '"' + temp + '"'
    nm = run_scan(targets)

    print(f"Command run: {nm.command_line()}")

    data = extract_results(nm)
    print(f"Found {len(nm.all_hosts())} hosts:")
    for row in data:
        print(row)
        print("-------------------------------")

if __name__ == "__main__":
    main()