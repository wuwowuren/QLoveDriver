#include "DISABLE_PATHGUARD.h"





typedef struct _PATHGUARD_INFO
{
	KSPIN_LOCK * ExpLargePoolTableLock;
	PVOID PoolBigPageTable;
	DWORD64 * PoolBigPageTableSize;

}PATHGUARD_INFO,*PPATHGUARD_INFO;





//BOOLEAN _cmpByte(,)



//-----------------------------  BigPool -----------------------------------//

// ≤È’“ SEARCH

ULONGLONG  getRoutineAddress(wchar_t* name) {
	UNICODE_STRING fName;
	RtlInitUnicodeString(&fName, name);
	PVOID fAddress = MmGetSystemRoutineAddress(&fName);
	return (ULONGLONG)fAddress;
}



