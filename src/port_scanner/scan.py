import socket
import os


def tcp_connect_scan(host_ip, start_port, end_port):
    open_ports_count = 0
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            res = sock.connect_ex((host_ip, port))
            if res == 0:
                open_ports_count += 1
                print(f'Port {port} is open')
            sock.close()
    except KeyboardInterrupt:
        print("Scan terminated by user")
        pass
    
    print(f'{open_ports_count} port(s) open')

def tcp_syn_scan(host_ip, start_port, end_port):
    open_ports_count = 0
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # 
            sock.close()
    except KeyboardInterrupt:
        print("Scan terminated by user")

def ping_sweep(network_ip):
    alive_hosts_count = 0
    try:
        for i in range(1, 255):
            host = network_ip + str(i)
            res = os.system(f'ping -c 1 -w 1 {host} > /dev/null')
            if res == 0:
                print(f'{host} is up')
                alive_hosts_count += 1

        print(f'{alive_hosts_count} host(s) up')
    except KeyboardInterrupt:
        print("Scan terminated by user")


def scan(type):
    if type == 1:
        print("Specify the IPv4 address of the host to scan:", end=" ")
        host = input()
        host_ip = socket.gethostbyname(host)
        print(host_ip)
        print("Specify the port range to scan")  # need to handle unexpected inputs
        print("Start port (if not specified, defaults to 0):", end=" ")
        start_port = input()
        if start_port == "":
            start_port = 0
        print("End_port (if not specified, defaults to 1023):", end=" ")
        end_port = input()
        if end_port == "":
            end_port = 1023
        tcp_connect_scan(host_ip, int(start_port), int(end_port))

    elif type == 3:
        print("Specify the network IPv4 address to scan:", end=" ")
        ip = input()
        third_dot_index = ip.rfind(".")
        ip = ip[:third_dot_index + 1]
        ping_sweep(ip)





print("Select the type of scan")  # need to handle unexpected inputs
print("1 - TCP Connect Scan")
print("2 - TCP SYN Scan")
print("3 - Ping Sweep")

type = int(input())
scan(type)

