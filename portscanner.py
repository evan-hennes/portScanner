import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# scan single port @ single IP address
def scanport(addr, p, to):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(to)
    try:
        s.connect((str(addr), p))
        return addr, p, True, None
    except Exception as e:
        return addr, p, False, e
# end def scanport

# utilize thread pool to scan multiple ports thru range of IP addresses
def portscan(rng, to, ts):
    network = ipaddress.ip_network(rng)
    executor = ThreadPoolExecutor(max_workers = len(ts) * network.num_addresses)
    tasks = [executor.submit(scanport, addr, p, to) for addr in network for p in ts]
    openPorts = []
    for f in as_completed(tasks):
        addr, port, isOpen, e = f.result()
        if isOpen:
            # print(f'Successfully connected to port {addr}:{port}')
            openPorts.append((addr, port))
        else:
            # print(f'Failed to connect to port {addr}:{port} - {e}')
            continue
    return openPorts
# end def portscan

# main program area
if __name__ == '__main__':
    # port values for telnet, ftp (control + data), SSH, smtp (non-encrypted + encrypted/submission), http, imap (non-encrypted + encrypted/IMAPS), and https 
    toscan = [23, 21, 20, 22, 25, 587, 80, 143, 993, 443]
    inp = input('Enter the range of IP addresses you\'d like to scan: ')
    to = float(input('Enter your preferred timeout value: '))
    openPorts = portscan(inp, to, toscan)
    for port in openPorts:
        print(f'Port {port[0]}:{port[1]} is open')
# end main program area