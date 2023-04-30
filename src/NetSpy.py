from packet_analyzer import analyzer
from port_scanner import scan

print("    _   __     __  _____  ")          
print("   / | / /__  / /_/ ___/____  __  __")
print("  /  |/ / _ \/ __/\__ \/ __ \/ / / /")
print(" / /|  /  __/ /_ ___/ / /_/ / /_/ /") 
print("/_/ |_/\___/\__//____/ .___/\__, /")  
print("                    /_/    /____/")
print()

print("Choose one of the options")
print("1 - Packet Sniffer")
print("2 - Port Scanner")
mode = input()

if mode == "1":
    analyzer.run()
elif mode == "2":
    scan.run()
else:
    print("Invalid option")