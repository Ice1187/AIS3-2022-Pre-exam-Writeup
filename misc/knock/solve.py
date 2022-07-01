import scapy.all as scapy

packets = scapy.rdpcap('./knock.pcapng')

knock_packets = packets[scapy.UDP][12:]

flag = ''
for p in knock_packets:
    flag += chr(p.dport - 12000)

print(flag)

# Flag: AIS3{kn0ckKNOCKknock}
