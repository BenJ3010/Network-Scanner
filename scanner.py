import nmap

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

def main():
    temp = input("Enter target IPs: ")
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