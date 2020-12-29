import pyshark
import time
import re

# define interface
networkInterface = "enp0s3"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface) 

print("listening on %s" % networkInterface)

# scan for five network packages
# print(" ")
# print("Scan for 5 packets")
#
# for pkt in capture.sniff_continuously(packet_count=5):
#     # default output
#     print(pkt)
    
# scan for five network packages and display header + content
print(" ")
print("Scan for 10 packages for being TCP, UDP or IPv4 packets")

for pkt in capture.sniff_continuously(packet_count=10):
    # adjusted output
    try:
        # get timestamp
        localtime = time.asctime(time.localtime(time.time()))
        
        # get packet content
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[protocol].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[protocol].dstport
        flags = ""

        # output packet info
        print ("%s IP %s:%s <-> %s:%s (%s): Flags: %s" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol, flags))

        # output packet data
        print ("data:")
        payload = pkt.tcp.payload
        payloadEntries = payload.split(":")
        position = 10
        n = m = 0
        while n < len(payloadEntries):
            m = m + 16
            positionString = "%04d" % position
            dataString = " ".join(payloadEntries[n:m])

            # prepare ascii output
            asciibasis = dataString.replace(" ","")
            asciiString = bytearray.fromhex(asciibasis).decode('latin-1')
            pattern3 = re.compile("[^a-z0-9]", re.IGNORECASE)
            asciiString = re.sub(pattern3, ".", asciiString)

            # combine 2x2 letters
            pattern1 = re.compile("([a-z0-9]{2})\s([a-z0-9]{2})")
            pattern2 = r"\1\2"
            dataString = re.sub(pattern1, pattern2, dataString)
            # make sure the string is exactly 40 characters
            dataString = dataString.ljust(40)

            print ("0x%s: %s %s" % (positionString, dataString, asciiString))
            n = m
            position = position + 10

    except AttributeError as e:
#        # ignore packets other than TCP, UDP and IPv4
       pass
    print (" ")
 
