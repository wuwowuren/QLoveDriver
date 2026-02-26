#include "BrotherEncrypt.h"



unsigned int _hEncrypt(unsigned int RandSgin, void* pDate, unsigned int Size) {
	char* pBuffer = (char*)pDate;
	unsigned int TempChenk = RandSgin;
	for (unsigned int i = 0; i < Size; i++) {
		unsigned int TempA = TempChenk << 6;
		unsigned int TempB = TempChenk >> 2;
		TempA = TempA + TempB;
		TempB = pBuffer[i] & 0xFF;
		TempA = TempA + TempB + 0x9E3779B9;
		TempChenk = TempA ^ TempChenk;
	}
	return TempChenk;
}

void _hEncrypt_DEC(unsigned int RandSgin, void* pDate, unsigned int Size) {
	char* pBuffer = (char*)pDate;
	unsigned int TempChenk = RandSgin;
	for (unsigned int i = 0; i < Size; i++) {
		unsigned int TempA = TempChenk << 6;
		unsigned int TempB = TempChenk >> 2;
		TempA = TempA + TempB;
		TempB = TempChenk & 0xFF;
		TempA = TempA + TempB + 0x9E3779B9;
		TempChenk = TempA ^ TempChenk;
		pBuffer[i] = pBuffer[i] ^ TempChenk;
	}
}