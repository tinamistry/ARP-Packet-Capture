# ARP-Packet-Capture
To get the arp packets form the pcap file, I looped through the file and checked to see if a file was 
of type ARP. I used ethernet to parse the file. Then to get the arp header I sliced the buffer 
from the bytes 14-42 the packet was read into. Then I unpacked the header using struct.unpack. 
Since unpack returns a string I used [] to get the bytes that corresponding to various parts of the header. 
To format the addresses I hexlify to convert to hexadecimal and then formatted it with a colon. 
