This is a secure coding review project using static methods in Windows OS.
I have used Bandit and Pylint to review my Network Packet Sniffer code.
The tool captures and processes network packets, displaying details of Ethernet, IPv4, ICMP, TCP, and UDP protocols.

To install Bandit:
pip install bandit
(Add the path in User Variable section of Environment Variable if issue persist)

To install Pylint:
pip install pylint
(Add the path in User Variable section of Environment Variable if issue persist)

Files:
CodeAlpha_Network_Packet_Sniffer.py: Initial version of the packet sniffer, with a Pylint score of 4.6/10.
codealpha_network_packet_sniffer_edited.py: Improved version of the packet sniffer, with a Pylint score of 8.64/10.

To run Bandit:
1. cd Path\to\File
2. python -m bandit pythonfile.py

To run Pylint:
1. cd Path\to\File
2. python -m pylint pythonfile.py

Bandit Results:
Static Code Analysis: No issues were identified by Bandit for security vulnerabilities.

Pylint Review
First Version (CodeAlpha_Network_Packet_Sniffer.py): Score: 4.6/10
Issues: Long lines, unused variables, lack of f-strings, and complex functions with too many local variables.

Second Version (codealpha_network_packet_sniffer_edited.py): Score: 8.64/10
Improvements: Resolved most long lines, switched to f-strings, reduced the complexity of functions, and removed unused variables.
