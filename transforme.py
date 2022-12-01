import struct
import datetime
 
fpcap = open('trace/trace.pcap', 'rb')
ftxt = open('trace/trace.txt', 'w')
string_data = fpcap.read()
packet_num = 0
packet_data = []
packet_time = []
 
pcap_packet_header = {}
i = 24
 
while(i < len(string_data)):
    packet_time.append(string_data[i:i+4])
    packet_len = struct.unpack('I', string_data[i+12:i+16])[0]
    packet_data.append(string_data[i+16:i+16+packet_len])
    i = i + packet_len + 16
    packet_num += 1
 
def bytes_to_hex(a):
    if a < 16:
        return "0"+hex(a)[2:]
    else:
        return hex(a)[2:]
 
for i in range(packet_num):
    ftxt.write('Num trame'+str(i+1) +':\n')

    for j in range(0, len(packet_data[i])):
        ftxt.write(bytes_to_hex(packet_data[i][j])+" ")
    ftxt.write('\n\n')
 
 
fpcap.close()
ftxt.close()