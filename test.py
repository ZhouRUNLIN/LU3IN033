from analyse import *
t="b0 73 5d 82 cb 84 d8 5e d3 ab 78 f0 08 00 45 00 00 28 71 c1 40 00 80 06 00 00 c0 a8 03 c4 3d a0 ca 66 e1 d1 01 bb 52 dc 67 b6 2b f3 a5 09 50 10 20 0f cc 8d 00 00"
t=t.upper()
print(decode_no_CRC(t))