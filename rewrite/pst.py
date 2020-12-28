
# written by Frank Hofmann <frank,hofmann@efho.de>

import pyshark

# define interface
networkInterface = "enp0s3"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface)

print("listening on %s" % networkInterface)

# scan for five network packages
print(" ")
print("Scan for 5 packets")

for pkt in capture.sniff_continuously(packet_count=5):
    # default output
    print(pkt)
    
# scan for five network packages and display header + content
print(" ")
print("Scan for 5 packages for being TCP, UDP or IPv4 packets")

for pkt in capture.sniff_continuously(packet_count=5):
    # adjusted output
    try:
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[protocol].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[protocol].dstport
        print ("%s %s:%s -> %s:%s" % (protocol, src_addr, src_port, dst_addr, dst_port))
        print ("data:")
        payload = pkt.tcp.payload
        payloadEntries = payload.split(":")
        position = 10
        n = m = 0
        while n < len(payloadEntries):
            m = m + 16
            positionString = "%04d" % position
            dataString = " ".join(payloadEntries[n:m])
            print ("0x%s: %s" % (positionString, dataString))
            n = m
            position = position + 10

    except AttributeError as e:
#        # ignore packets other than TCP, UDP and IPv4
       pass
 
