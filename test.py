from analyse import *
t="f8 4d 89 85 ee 46 8c fd de c5 b6 cc 08 00 45 00 00 47 84 71 40 00 30 06 bd fb b7 02 8f 6c c0 a8 01 2d 01 bb c0 a3 6e fc 02 d3 0d 9f a4 bd 50 18 01 f5 14 80 00 00 15 03 03 00 1a f5 71 69 40 6d d2 dc fb 32 1f 44 53 a6 39 8e f3 15 33 a3 1a 0f f5 b5 7a 93 9a "
print(decode_simplified(t))
packet_num=1
print(str(packet_num) + " packages have been captured")