#include "BASE_TABLE.h"
#include <wdm.h>
#include <ntimage.h>
#include "PAGE_CR0_DISABLE.h"

//#pragma warning(disable:4819)


#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"%d" format,__LINE__, __VA_ARGS__)
#else
#define LOG_DEBUG(format,...) 

#endif // DEBUG

static ULONGLONG pKeServiceDescriptorTable = 0;
static ULONGLONG pKeServiceDescriptorTable2 = 0;
static ULONGLONG pKeServiceDescriptorTableShow = 0;
static ULONGLONG bServiceTable64 = 0;



DWORD64 KernelBaseSize = 0;
ULONG_PTR kernelBase = 0;
ULONG_PTR Win32kBase = 0;
ULONG_PTR Win32kBaseBase = 0;
ULONG_PTR Win32kBaseFull = 0;
ULONG _Begin_TEXT = 0;
ULONG _Lenth_TEXT = 0;

NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

typedef NTSTATUS(NTAPI *QuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);


static QuerySystemInformation NtQuerySystemInformation = 0 ;



//__kernel_entry NTSTATUS NtQuerySystemInformation(
//	           SYSTEM_INFORMATION_CLASS SystemInformationClass,
//	       PVOID                    SystemInformation,
//	            ULONG                    SystemInformationLength,
//	 PULONG                   ReturnLength
//);


NTSTATUS NTAPI _ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	if (NtQuerySystemInformation == NULL)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");

		NtQuerySystemInformation = (QuerySystemInformation)MmGetSystemRoutineAddress(&routineName);
		LOG_DEBUG("NtQuerySystemInformation %I64X\n",NtQuerySystemInformation);
		if (NtQuerySystemInformation == NULL)
		{
		    return STATUS_FAIL_CHECK;
		}
		//LOG_DEBUG("NtQuerySystemInformation <%p>\n", NtQuerySystemInformation);
		//return STATUS_FAIL_CHECK;
	}
	return NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}


typedef PIMAGE_NT_HEADERS (NTAPI * nRtlImageNtHeader)(_In_ PVOID Base);


PVOID GetKernelBase(PULONG pImageSize)
{
	typedef struct _SYSTEM_MODULE_ENTRY
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

	ULONG SystemInfoBufferSize = 0;

	NTSTATUS status = _ZwQuerySystemInformation(SystemModuleInformation,
		NULL,
		0,
		&SystemInfoBufferSize);

	LOG_DEBUG("SystemInfoBufferSize Szie %d\n", SystemInfoBufferSize);


	//sizeof(SYSTEM_MODULE_INFORMATION)

	if (!SystemInfoBufferSize)
	{
		LOG_DEBUG("_ZwQuerySystemInformation ERROR %I64X\n", status);
		return NULL;
	}

	LOG_DEBUG("SystemInfoBufferSize Szie %d\n", SystemInfoBufferSize);

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, SystemInfoBufferSize * 2,'tag');

	if (!pSystemInfoBuffer)
	{
		LOG_DEBUG("_ZwQuerySystemInformation ExAllocatePool ERROR\n");
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	status = _ZwQuerySystemInformation(
		SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	LOG_DEBUG("nCount %d   size %08X\n", pSystemInfoBuffer->Count, SystemInfoBufferSize);

	//sizeof(SYSTEM_MODULE_ENTRY)

	if (NT_SUCCESS(status))
	{
		pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
		LOG_DEBUG("Kenerl: %s  %I64X\n", pSystemInfoBuffer->Module[0].FullPathName, pModuleBase);
		
		if (pImageSize)
			*pImageSize = pSystemInfoBuffer->Module[0].ImageSize;



		//ANSI_STRING Win32KString;
		//RtlInitAnsiString(&Win32KString, "win32k.sys");

		UNICODE_STRING Win32KStringFULL; 
		RtlInitUnicodeString(&Win32KStringFULL, L"*WIN32KFULL.SYS");

		UNICODE_STRING Win32KStringBASE;
		RtlInitUnicodeString(&Win32KStringBASE, L"*WIN32KBASE.SYS");

		UNICODE_STRING Win32KString;
		RtlInitUnicodeString(&Win32KString, L"*WIN32K.SYS");
		for (size_t i = 0; i < pSystemInfoBuffer->Count; i++){

			ANSI_STRING ModString;
			RtlInitAnsiString(&ModString, pSystemInfoBuffer->Module[i].FullPathName);

			UNICODE_STRING uModString;
			RtlAnsiStringToUnicodeString(&uModString, &ModString, TRUE);


			if (FsRtlIsNameInExpression(&Win32KString, &uModString, TRUE, 0))
			{
				Win32kBase = (ULONG_PTR)pSystemInfoBuffer->Module[i].ImageBase;
	            LOG_DEBUG("Win32kBase  Win32k <%p>\n", Win32kBase);
				//break;
			}
			if (FsRtlIsNameInExpression(&Win32KStringBASE, &uModString, TRUE, 0))
			{
				Win32kBaseBase = (ULONG_PTR)pSystemInfoBuffer->Module[i].ImageBase;
				LOG_DEBUG("Win32KStringBASE  Win32k <%p>\n", Win32kBase);
				//break;
			}
			if (FsRtlIsNameInExpression(&Win32KStringFULL, &uModString, TRUE, 0))
			{
				Win32kBaseFull = (ULONG_PTR)pSystemInfoBuffer->Module[i].ImageBase;
				LOG_DEBUG("Win32kBaseFull  Win32k <%p>\n", Win32kBase);
				//break;
			}
			RtlFreeUnicodeString(&uModString);
			if (Win32kBase !=0 && Win32kBaseBase != 0 && Win32kBaseFull != 0)
			{
				break;
			}
		}
	}

#ifdef DEBUG

	//pSystemInfoBuffer->Module[]
	

#endif


	ExFreePoolWithTag(pSystemInfoBuffer, 'tag');
	return pModuleBase;
}






extern PVOID FindImageBase(wchar_t* pBaseName, ULONG64* nSize);

ULONGLONG getKeServiceDescriptorTable7_10()
{
	//if (pKeServiceDescriptorTable != 0)
	//{
	//	return pKeServiceDescriptorTable;
	//}
		//x64 code


	//

	//KDPC*  = (KDPC*)(KiWaitNever ^ __ROR8__(
	//	(unsigned __int64)Timer ^ _byteswap_uint64((unsigned __int64)Dpc ^ KiWaitAlways),
	//	KiWaitNever));

	//KeSetTimerEx()


	__try {
		ULONG64 kernelSize = 0;
		
	
		kernelBase = (ULONG_PTR)FindImageBase(L"ntoskrnl.exe", &kernelSize);    //(ULONG_PTR)GetKernelBase(&kernelSize);

		ULONG64 Win32kSize = 0;

		Win32kBaseFull = (ULONG_PTR)FindImageBase(L"WIN32KFULL.SYS", &Win32kSize);

		Win32kBaseBase = (ULONG_PTR)FindImageBase(L"WIN32KBASE.SYS", &Win32kSize);

		Win32kBase = (ULONG_PTR)FindImageBase(L"WIN32K.SYS", &Win32kSize);


		LOG_DEBUG("Win32kBaseFull %I64X   Win32kBaseBase %I64X  Win32kBase %I64X", Win32kBaseFull, Win32kBaseBase, Win32kBase);


		if (kernelBase == 0 || kernelSize == 0) {

			LOG_DEBUG("GetKernelBase ERROR\n");
			return 0;
		}
		KernelBaseSize = kernelSize;
		const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(kernelBase);
		const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(kernelBase)+ dos_header->
			e_lfanew);
		const USHORT section_size = pNtHeader->FileHeader.NumberOfSections;
		const PIMAGE_SECTION_HEADER sections_array = (PIMAGE_SECTION_HEADER)((PUCHAR)(pNtHeader)+sizeof(
			IMAGE_NT_HEADERS));
		for (auto i = 0; i < section_size; i++) {

			if (_stricmp(sections_array[i].Name, ".text") == 0)
			{
				ULONG64 scan_base = (ULONG64)(kernelBase)+sections_array[i].VirtualAddress;
				int scan_size = max(sections_array[i].SizeOfRawData, sections_array[i].Misc.VirtualSize);
				_Begin_TEXT = sections_array[i].VirtualAddress;
				_Lenth_TEXT = scan_size;

				LOG_DEBUG("TEXT <%08X>  <%08X>\n", _Begin_TEXT, _Lenth_TEXT);

			}
		}
		//	return 0;


		

		PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
		PIMAGE_SECTION_HEADER textSection = NULL;
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
		for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
		{
			char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
			RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
			sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
			if (strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0)
			{
				textSection = section;
				break;
			}
			section++;
		}
		if (textSection == NULL)
		{
			LOG_DEBUG("textSection ERROR\n");
			return 0;
		}



		//LOG_DEBUG(" kernelBase :<%p> textSection->VirtualAddress:<%p> textSection->Misc.VirtualSize : %08X ERROR\n", kernelBase, textSection->VirtualAddress, textSection->Misc.VirtualSize);




		// Find KiSystemServiceStart in .text
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		BOOLEAN found = 0;
		ULONG KiSSSOffset;


		//KIRQL irql = WPOFFx64();

		for (KiSSSOffset = 0; KiSSSOffset < textSection->Misc.VirtualSize - signatureSize; KiSSSOffset++)
		{
			if (RtlCompareMemory(((unsigned char*)kernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
			{
				found = 1;
				break;
			}
		}
		if (!found) {


			LOG_DEBUG("found ERROR\n");
			return 0;

		}



		// lea r10, KeServiceDescriptorTable

	// h



		//return 0;



		ULONG_PTR address = kernelBase + textSection->VirtualAddress + KiSSSOffset + signatureSize;
		LONG relativeOffset1 = 0;
		LONG relativeOffset2 = 0;

		//KIRQL irql = WPOFFx64();
		//irql = WPOFFx64();
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{

			relativeOffset1 = *(LONG*)(address + 3);

			relativeOffset2 = *(LONG*)(address + 3 + 7);

		}
		//WPONx64(irql);


		LOG_DEBUG("Found IP<%p>\n", address);

		//HideMemory((PVOID)address,0,0);


		//return 0;


		if (relativeOffset1 == 0)
		{
			LOG_DEBUG("found2 ERROR\n");
			return 0;
		}
		pKeServiceDescriptorTable = (ULONGLONG)(address + relativeOffset1 + 7);
		pKeServiceDescriptorTable2 = (ULONGLONG)(address + 7 + relativeOffset2 + 7);
		pKeServiceDescriptorTableShow = pKeServiceDescriptorTable2 + 0x20;
		// SSDT 和 SSDTSHOW 本质上是挨着一起的



		LOG_DEBUG("Table : <%p>   TableShow : <%p>\n", pKeServiceDescriptorTable, pKeServiceDescriptorTableShow);


		return pKeServiceDescriptorTable;
	}
	__except (1) {


		LOG_DEBUG("%s   __except : <%08X>\n", __FUNCTION__, GetExceptionCode());

		return 0;

	}
}


//WIN7 64
//ULONGLONG GetKeServiceDescriptorTable64()
//{
//	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
//	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
//	PUCHAR i = NULL;
//	UCHAR byte1 = 0, byte2 = 0, byte3 = 0;
//	ULONG temp = 0;
//	ULONGLONG addr = 0;
//	//开始搜索
//	for (i = StartSearchAddress; i < EndSearchAddress; i++)
//	{
//		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
//		{
//			byte1 = *i;
//			byte2 = *(i + 1);
//			byte3 = *(i + 2);
//			if (byte1 == 0x4c && byte2 == 0x8d && byte3 == 0x15) //4c8d15
//			{
//				memcpy(&temp, i + 3, 4);
//				addr = (ULONGLONG)temp + (ULONGLONG)i + 7;
//				return addr;
//			}
//		}
//	}
//	return 0;
//}

ULONGLONG getKeServiceDescriptorTable() {

	if (pKeServiceDescriptorTable == 0)
	{
		getKeServiceDescriptorTable7_10();
	}
	return pKeServiceDescriptorTable;
}
unsigned long long getKeServiceDescriptorTable2()
{
	if (pKeServiceDescriptorTable2 == 0)
	{
        getKeServiceDescriptorTable7_10();
	}
	return pKeServiceDescriptorTableShow;
}
ULONGLONG getKeServiceDescriptorTableShow() {

	if (pKeServiceDescriptorTableShow == 0)
	{
		getKeServiceDescriptorTable7_10();
	}
	return pKeServiceDescriptorTableShow;
}