import struct
import dpkt
import binascii
from ast import literal_eval


def packetCapture():
    f = open('assignment4_my_arp.pcap', 'rb')
    i = 0
    pcap = dpkt.pcap.Reader(f)
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        if isinstance(eth.data, dpkt.arp.ARP): #if its in arp packet
            arp = buffer[14:42]
            arp = struct.unpack('!HHBBH6s4s6s4s', arp)



            hardware_type = arp[0]
            protocol_type = arp[1]
            hardware_length = arp[2]
            protocol_length = arp[3]
            operation_type = arp[4]
            sender_mac_address = binascii.hexlify(arp[5],':',1).decode('utf-8')
            sender_protocol_address = binascii.hexlify(arp[6],':',1).decode('utf-8')
            reciever_mac_address = binascii.hexlify(arp[7], ':', 1).decode('utf-8')
            reciever_protocol_address = binascii.hexlify(arp[8],':',1).decode('utf-8')
            if i == 1:
                 print("Request:")
                 print('Sender MAC address: ', sender_mac_address)
                 print('Reciever MAC address:', reciever_mac_address)
                 print('Hardware type: ', hardware_type)
                 print('Protocol type: ', protocol_type)
                 print('Hardware_length: ', hardware_length)
                 print('Protocol type: ', protocol_length)
                 print('Operation type: ', operation_type)
                 print('Sender protocol address: ', sender_protocol_address)
                 print('Reciever protocl address: ', reciever_protocol_address)
            if i == 2:
                print("Response:")
                print('Sender MAC address: ', sender_mac_address)
                print('Reciever MAC address:', reciever_mac_address)
                print('Hardware type: ', hardware_type)
                print('Protocol type: ', protocol_type)
                print('Hardware_length: ', hardware_length)
                print('Protocol type: ', protocol_length)
                print('Operation type: ', operation_type)
                print('Sender protocol address: ', sender_protocol_address)
                print('Reciever protocl address: ', reciever_protocol_address)

            i += 1

packetCapture()
