from analyse import *
s="08 00 20 0A AC 96 08 00 20 0A 70 66 08 00 4F 00 00 7C CB C9 00 00 FF 01 B9 7F 84 E3 3D 05 C0 21 9F 06 07 27 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 A2 56 2F 00 00 00 29 36 8C 41 00 03 86 2B 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37"
print(decode_no_CRC(s))
arp="FF FF FF FF FF FF F0 B4 29 13 15 CC 08 06 00 01 08 00 06 04 00 01 F0 B4 29 13 15 CC C0 A8 1F 01 00 00 00 00 00 00 C0 A8 1F 02"
print(decode_no_CRC(arp))