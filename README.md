# NetSpy

## Requirements

- A Linux system
- Python 3.x
- Scapy (Refer [https://scapy.readthedocs.io/en/latest/installation.html](https://scapy.readthedocs.io/en/latest/installation.html))

## Setup/Installation

- Open a terminal

- Clone the project repository by running
  
    `git clone https://github.com/ansbaby7/NetSpy.git`
  
    [Note: You need to have git installed to run this command]

- Run the program using the command `sudo python3 src/NetSpy.py`

## Using the Packet Analyzer module

![netspy1.png](images/netspy1.png)

![Screenshot from 2023-05-02 19-45-53.png](images/netspy2.png)

## Using the Port Scanner module

1. **TCP Connect Scan**

![Screenshot from 2023-05-02 20-04-34.png](images/netspy4.png)

2. **TCP SYN Scan**

![Screenshot from 2023-05-02 20-01-33.png](images/netspy3.png)

3. **Ping Sweep Scan**

Note: This scan currently supports only mask of /24 (CIDR)

![Screenshot from 2023-05-02 20-08-06.png](images/netspy5.png)
