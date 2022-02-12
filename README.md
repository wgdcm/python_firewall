## Python Firewall
This python program analyzes each and every packet which comes into the FW Servers and forward, drop according to the defined rules. 

### Requirements 
-Linux operating system with 2 network interfaces.

-Install Python3.

    sudo apt-get update
    sudo apt-get install python3.6
    
### Setup

Create 2 network interfaces.
Assign any IP address for the interfaces.
All firewall rules can define in the rules.conf file.
When you run the program, the rules.conf file must be in the same directory.
The contents of the rules.conf file includes how to use it.


### How to run
Run this command in a Linux environment.
```
sudo python3 firewall.py
```
You will be asked what are two interfaces you need to run the program.

Provide the correct interface names for the program.

### Note

The firewall program reads these rules from top to bottom.<br>
You can define ACL rules based on priority.<br>
In the first field, you can define "ALLOW" or "DENY". Other words are not allowed.<br>
In the second field, you can define the protocol. Permitted protocols are "TCP", "UDP" and "ICMP".<br>
In the third field, you can define the source IP or type "any" to accept all IP addresses.<br>
In the fourth field, you can define the destination IP or type "any" to accept all IP addresses.<br>
Separate each field with a comma.<br>

ex: ***allow, icmp, any, any***
