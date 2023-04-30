import socket
import os
import threading

def scan_ports(host_ip, start, end):
    for port in range(start, end  + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        res = sock.connect_ex((host_ip, port))
        if res == 0:
            print(f'Port {port} is open')
        sock.close()

def tcp_connect_scan(host_ip, start_port, end_port, num_threads=30):
    threads = []
    subrange_size = (end_port - start_port + 1) // num_threads
    if subrange_size < 1:
        num_threads = 1
    subranges = []

    for i in range(num_threads):
        start = start_port + i * subrange_size
        end = start_port + (i + 1) * subrange_size - 1
        if i == num_threads - 1:
            end = end_port
        subranges.append((start, end))
    
    for start, end in subranges:
        t = threading.Thread(target=scan_ports, args=(host_ip, start, end))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def tcp_syn_scan(host_ip, start_port, end_port):
    open_ports_count = 0
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # 
            sock.close()
    except KeyboardInterrupt:
        print("Scan terminated by user")

def ping_hosts(network_ip, start, end):
    for i in range(start, end + 1):
        host = network_ip + str(i)
        res = os.system(f'ping -c 1 -w 2 {host} > /dev/null')
        if res == 0:
            print(f'{host} is up')

def ping_sweep(network_ip, num_threads=20):
    threads = []
    subrange_size = (254 - 1 + 1) // num_threads
    if subrange_size < 1:
        num_threads = 1
    subranges = []

    for i in range(num_threads):
        start = 1 + i * subrange_size
        end = 1 + (i + 1) * subrange_size - 1
        if i == num_threads - 1:
            end = 254
        subranges.append((start, end))
    
    for start, end in subranges:
        t = threading.Thread(target=ping_hosts, args=(network_ip, start, end))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()


def scan(type):
    if type == "1":
        print("Specify the IPv4 address or hostname to scan:", end=" ")
        host = input()
        host_ip = socket.gethostbyname(host)
        print(host_ip)
        print("Specify the port range to scan")  # need to handle unexpected inputs
        print("Start port (if not specified, defaults to 1):", end=" ")
        start_port = input()
        if start_port == "" or start_port == 0:
            start_port = 1
        print("End_port (if not specified, defaults to 1024):", end=" ")
        end_port = input()
        if end_port == "":
            end_port = 1024
        tcp_connect_scan(host_ip, int(start_port), int(end_port))
    
    elif type == "2":
        pass

    elif type == "3":
        print("Specify the network IPv4 address to scan:", end=" ")
        ip = input()
        third_dot_index = ip.rfind(".")
        ip = ip[:third_dot_index + 1]
        ping_sweep(ip)

def run():
    print("Select the type of scan")  # need to handle unexpected inputs
    print("1 - TCP Connect Scan")
    print("2 - TCP SYN Scan")
    print("3 - Ping Sweep")

    type = input()
    scan(type)

