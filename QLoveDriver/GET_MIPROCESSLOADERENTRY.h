#pragma once
#ifndef GET_MIPROCESSLOADERENTRY_H
#define GET_MIPROCESSLOADERENTRY_H

#include <ntddk.h>

#include "DEBUG_LOG.h"

typedef NTSTATUS(__fastcall *MiProcessLoaderEntry)(PVOID pDriverSection, BOOLEAN bLoad);

PVOID GetProcAddressK(WCHAR *FuncName)
{
	UNICODE_STRING u_FuncName = { 0 };
	RtlInitUnicodeString(&u_FuncName, FuncName);
	return MmGetSystemRoutineAddress(&u_FuncName);
}

//在Windows 7的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_7()
{
	//这个Search_Code就是MiProcessLoaderEntry函数的最前面的操作码
	//WIN7的搜索很有趣，MiProcessLoaderEntry这个函数就在EtwWriteString函数的前面几个函数
	//所以直接搜索EtwWriteString函数然后向前搜索即可
	CHAR Search_Code[] = "\x48\x89\x5C\x24\x08"			//mov     [rsp+arg_0], rbx
						 "\x48\x89\x6C\x24\x18"			//mov     [rsp+arg_10], rbp
						 "\x48\x89\x74\x24\x20"			//mov     [rsp+arg_18], rsi
						 "\x57"							//push    rdi
						 "\x41\x54"						//push    r12
						 "\x41\x55"						//push    r13
						 "\x41\x56"						//push    r14
						 "\x41\x57";					//push    r15
	ULONG_PTR EtwWriteStringAddress = 0;
	ULONG_PTR StartAddress = 0;

	EtwWriteStringAddress = (ULONG_PTR)GetProcAddressK(L"EtwWriteString");
	StartAddress = EtwWriteStringAddress - 0x1000;
	if (EtwWriteStringAddress == 0)
		return NULL;

	while (StartAddress < EtwWriteStringAddress)
	{
		if (memcmp((CHAR*)StartAddress, Search_Code, strlen(Search_Code)) == 0)
			return (MiProcessLoaderEntry)StartAddress;
		++StartAddress;
	}

	return NULL;
}

//在Windows 8的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8()
{
	CHAR Search_Code[] = "\x48\x89\x5C\x24\x08"			//mov     [rsp+arg_0], rbx
						 "\x48\x89\x6C\x24\x10"			//mov     [rsp+arg_10], rbp
						 "\x48\x89\x74\x24\x18"			//mov     [rsp+arg_18], rsi
						 "\x57"							//push    rdi
						 "\x48\x83\xEC\x20"				//sub	  rsp, 20h
						 "\x48\x8B\xD9";				//mov     rbx, rcx
	ULONG_PTR IoInvalidateDeviceRelationsAddress = 0;
	ULONG_PTR StartAddress = 0;

	IoInvalidateDeviceRelationsAddress = (ULONG_PTR)GetProcAddressK(L"IoInvalidateDeviceRelations");
	StartAddress = IoInvalidateDeviceRelationsAddress - 0x1000;
	if (IoInvalidateDeviceRelationsAddress == 0)
		return NULL;

	while (StartAddress < IoInvalidateDeviceRelationsAddress)
	{
		if (memcmp((CHAR*)StartAddress, Search_Code, strlen(Search_Code)) == 0)
			return (MiProcessLoaderEntry)StartAddress;
		++StartAddress;
	}

	return NULL;
}

//在Windows 8.1的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8_1()
{
	//IoLoadCrashDumpDriver -> MmLoadSystemImage -> MiProcessLoaderEntry
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry
	//在WIN10中MmUnloadSystemImage是导出的，WIN8.1中未导出，所以只能走另一条路子，还好IoLoadCrashDumpDriver是导出的

	//在IoLoadCrashDumpDriver函数中用来搜索的Code
	CHAR IoLoadCrashDumpDriver_Code[] = "\x48\x8B\xD0"				//mov     rdx, rax
										"\xE8";						//call	  *******
	//在MmLoadSystemImage函数中用来搜索的Code
	CHAR MmLoadSystemImage_Code[] = "\x41\x8B\xD6"					//mov     edx, r14d	
									"\x48\x8B\xCE"					//mov	  rcx, rsi
									"\x41\x83\xCC\x04"				//or	  r12d, 4
									"\xE8";							//call    *******	
	ULONG_PTR IoLoadCrashDumpDriverAddress = 0;
	ULONG_PTR MmLoadSystemImageAddress = 0;
	ULONG_PTR StartAddress = 0;

	IoLoadCrashDumpDriverAddress = (ULONG_PTR)GetProcAddressK(L"IoLoadCrashDumpDriver");
	StartAddress = IoLoadCrashDumpDriverAddress;
	if (IoLoadCrashDumpDriverAddress == 0)
		return NULL;

	while (StartAddress < IoLoadCrashDumpDriverAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, IoLoadCrashDumpDriver_Code, strlen(IoLoadCrashDumpDriver_Code)) == 0)
		{
			StartAddress += strlen(IoLoadCrashDumpDriver_Code);								//跳过一直到call的code
			MmLoadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
			break;
		}
		++StartAddress;
	}

	StartAddress = MmLoadSystemImageAddress;
	if (MmLoadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MmLoadSystemImageAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, MmLoadSystemImage_Code, strlen(MmLoadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MmLoadSystemImage_Code);								 //跳过一直到call的code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

//在Windows 10的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10()
{
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry

	//在MmUnloadSystemImage函数中搜索的Code
	CHAR MmUnloadSystemImage_Code[] = "\x83\xCA\xFF"				//or      edx, 0FFFFFFFFh
									  "\x48\x8B\xCF"				//mov     rcx, rdi
									  "\x48\x8B\xD8"				//mov     rbx, rax
									  "\xE8";						//call    *******
	/*
	//在MiUnloadSystemImage函数中搜索的Code
	CHAR MiUnloadSystemImage_Code[] = "\x45\x33\xFF"				//xor     r15d, r15d
									  "\x4C\x39\x3F"				//cmp     [rdi], r15
									  "\x74\x18"					//jz      short
									  "\x33\xD2"					//xor     edx, edx
									  "\x48\x8B\xCF"				//mov     rcx, rdi
									  "\xE8";						//call	  *******
	*/
	ULONG_PTR MmUnloadSystemImageAddress = 0;
	ULONG_PTR MiUnloadSystemImageAddress = 0;
	ULONG_PTR StartAddress = 0;

	MmUnloadSystemImageAddress = (ULONG_PTR)GetProcAddressK(L"MmUnloadSystemImage");
	StartAddress = MmUnloadSystemImageAddress;
	if (MmUnloadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MmUnloadSystemImageAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, MmUnloadSystemImage_Code, strlen(MmUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MmUnloadSystemImage_Code);								//跳过一直到call的code
			MiUnloadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
			break;
		}
		++StartAddress;
	}

	StartAddress = MiUnloadSystemImageAddress;
	if (MiUnloadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MiUnloadSystemImageAddress + 0x600)
	{
		//分析ntoskrnl可以看出来，在不同版本的win10，call MiProcessLoaderEntry前面的操作不同
		//但是每次call MiProcessLoaderEntry之后都会mov eax, dword ptr cs:PerfGlobalGroupMask
		//所以这里根据0xEB(call) , 0x8B 0x05(mov eax)作为特征码

		/*if (memcmp((VOID*)StartAddress, MiUnloadSystemImage_Code, strlen(MiUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MiUnloadSystemImage_Code);								 //跳过一直到call的code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}*/
		if (*(UCHAR*)StartAddress == 0xE8 &&												//call
			*(UCHAR *)(StartAddress + 5) == 0x8B && *(UCHAR *)(StartAddress + 6) == 0x05)	//mov eax,
		{
			StartAddress++;																	//跳过call的0xE8
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}


MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10_2()
{
	UNICODE_STRING FuncName = { 0 };
	PUCHAR pfnMmUnloadSystemImage = NULL;
	PUCHAR pfnMiUnloadSystemImage = NULL;
	PUCHAR pfnMiProcessLoaderEntry = NULL;

	RtlInitUnicodeString(&FuncName, L"MmUnloadSystemImage");
	pfnMmUnloadSystemImage = (PUCHAR)MmGetSystemRoutineAddress(&FuncName);

	if (pfnMmUnloadSystemImage && MmIsAddressValid(pfnMmUnloadSystemImage) && MmIsAddressValid((PVOID)((ULONG64)pfnMmUnloadSystemImage + 0xFF)))
	{
		/*
		PAGE:00000001403B1D80 48 8B D8                          mov     rbx, rax
		PAGE:00000001403B1D83 E8 D0 10 03 00                    call    MiUnloadSystemImage
		PAGE:00000001403B1D88 48 8B CB                          mov     rcx, rbx
		*/
		for (PUCHAR start = pfnMmUnloadSystemImage; start < pfnMmUnloadSystemImage + 0xFF; ++start)
		{
			if (*(PULONG)start == 0xE8D88B48 && *(PUINT16)(start + 8) == 0x8B48 && start[0xA] == 0xCB)
			{
				start += 3;
				pfnMiUnloadSystemImage = start + *(PLONG)(start + 1) + 5;
				LOG_DEBUG("pfnMiUnloadSystemImage = %p\n", pfnMiUnloadSystemImage);
			}
		}
	}
	LOG_DEBUG("enter\n");

	if (pfnMiUnloadSystemImage && MmIsAddressValid(pfnMiUnloadSystemImage) && MmIsAddressValid((PVOID)((ULONG64)pfnMiUnloadSystemImage + 0x600)))
	{
		//MiUnloadSystemImage
		//System        Length
		//15063         0X4FA
		//19043         0x69B
		//22000         0x7EF

		/*
				15063   19043   22000
		PAGE:00000001406EFE20                   loc_1406EFE20:                          ; CODE XREF: MiUnloadSystemImage+481↑j
		PAGE:00000001406EFE20                                                           ; MiUnloadSystemImage+49A↑j
		PAGE:00000001406EFE20 48 83 3B 00                       cmp     qword ptr [rbx], 0
		PAGE:00000001406EFE24 74 54                             jz      short loc_1406EFE7A
		PAGE:00000001406EFE26 33 D2                             xor     edx, edx
		PAGE:00000001406EFE28 48 8B CB                          mov     rcx, rbx
		PAGE:00000001406EFE2B E8 A4 F1 C7 FF                    call    MiProcessLoaderEntry
		PAGE:00000001406EFE30 8B 05 4A C6 60 00                 mov     eax, dword ptr cs:PerfGlobalGroupMask
		PAGE:00000001406EFE36 A8 04                             test    al, 4
		*/

		for (PUCHAR start = pfnMiUnloadSystemImage; start < pfnMiUnloadSystemImage + 0x600; ++start)
		{
			if (*(PUINT16)start == 0xD233 && *(PULONG)(start + 2) == 0xE8CB8B48 && *(PUINT16)(start + 0xA) == 0x058B && *(PUINT16)(start + 0x10) == 0x04A8)
			{
				start += 5;
				pfnMiProcessLoaderEntry = start + *(PLONG)(start + 1) + 5;
				LOG_DEBUG("pfnMiProcessLoaderEntry = %p\n", pfnMiProcessLoaderEntry);
				return (MiProcessLoaderEntry)pfnMiProcessLoaderEntry;
			}
		}
	}
	return NULL;
}

//根据系统判断调用哪个函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry()
{
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
	RTL_OSVERSIONINFOEXW OsVersion = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
	if (!NT_SUCCESS(Status))
	{
		LOG_DEBUG("获取系统版本失败！\n");
		return NULL;
	}

	if (OsVersion.dwMajorVersion == 10)								//如果是Windows 10
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10_2();
		LOG_DEBUG("当前系统版本是Windows 10 %d\n", OsVersion.dwBuildNumber);

		if (m_MiProcessLoaderEntry == 0)
		{
			m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10();
		}

		if (m_MiProcessLoaderEntry == NULL)
		{
			LOG_DEBUG("获取不到MiProcessLoaderEntry！\n");
		}
		else
		{
			LOG_DEBUG("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry);
		}
		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 3)
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8_1();
		LOG_DEBUG("当前系统版本是Windows 8.1\n");
		if (m_MiProcessLoaderEntry == NULL)
		{
			LOG_DEBUG("获取不到MiProcessLoaderEntry！\n")
		}
		else {
			LOG_DEBUG("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry);
		}

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 2 && OsVersion.wProductType == VER_NT_WORKSTATION)		//这个是为了区分Windows 8和Windows Server 2012
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8();
		LOG_DEBUG("当前系统版本是Windows 8\n");
		if (m_MiProcessLoaderEntry == NULL)
		{
			LOG_DEBUG("获取不到MiProcessLoaderEntry！\n");
		}
		else {
			LOG_DEBUG("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry);
		}

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1 && OsVersion.wProductType == VER_NT_WORKSTATION)		//这个是为了区分Windows 7和Windows Server 2008 R2	
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_7();
		LOG_DEBUG("当前系统版本是Windows 7\n");
		if (m_MiProcessLoaderEntry == NULL) {
			LOG_DEBUG("获取不到MiProcessLoaderEntry！\n");
		}
		else {
			LOG_DEBUG("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry);
		}

		return m_MiProcessLoaderEntry;
	}

	LOG_DEBUG("当前系统不支持！\n");
	return NULL;
}

#endif