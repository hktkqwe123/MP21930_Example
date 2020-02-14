#include "hexdump.h"

ULONG hexdump(PUCHAR data, ULONG size)
{
	ULONG nResult = 0;
	for (ULONG i = 0; i < size; i += 16) {
		nResult += DEBUG("%08X |", i);
		for (ULONG j = 0; j < 16; j++) {
			if (i + j < size) {
				nResult += DEBUG(" %02X", data[i + j]);
			}
			else {
				nResult += DEBUG("   ");
			}
			if ((j + 1) % 8 == 0) {
				nResult += DEBUG(" ");
			}
		}
		nResult += DEBUG("|");
		for (ULONG j = 0; j < 16; j++) {
			if (i + j < size) {
				UCHAR k = data[i + j];
				UCHAR c = k < 32 || k > 127 ? '.' : k;
				nResult += DEBUG("%c", c);
			}
			else {
				nResult += DEBUG(" ");
			}
		}
		nResult += DEBUG("\n");
	}
	return nResult;
}
