#include "KsSerial.h"



#define CBR_110             110
#define CBR_300             300
#define CBR_600             600
#define CBR_1200            1200
#define CBR_2400            2400
#define CBR_4800            4800
#define CBR_9600            9600
#define CBR_14400           14400
#define CBR_19200           19200
#define CBR_38400           38400
#define CBR_56000           56000
#define CBR_57600           57600
#define CBR_115200          115200
#define CBR_128000          128000
#define CBR_256000          256000

#define NOPARITY            0
#define ODDPARITY           1
#define EVENPARITY          2
#define MARKPARITY          3
#define SPACEPARITY         4

#define ONESTOPBIT          0
#define ONE5STOPBITS        1
#define TWOSTOPBITS         2

//------------------------------------------------  串口通信

typedef struct _DCB {
	DWORD DCBlength;      /* sizeof(DCB)                     */
	DWORD BaudRate;       /* Baudrate at which running       */
	DWORD fBinary : 1;     /* Binary Mode (skip EOF check)    */
	DWORD fParity : 1;     /* Enable parity checking          */
	DWORD fOutxCtsFlow : 1; /* CTS handshaking on output       */
	DWORD fOutxDsrFlow : 1; /* DSR handshaking on output       */
	DWORD fDtrControl : 2;  /* DTR Flow control                */
	DWORD fDsrSensitivity : 1; /* DSR Sensitivity              */
	DWORD fTXContinueOnXoff : 1; /* Continue TX when Xoff sent */
	DWORD fOutX : 1;       /* Enable output X-ON/X-OFF        */
	DWORD fInX : 1;        /* Enable input X-ON/X-OFF         */
	DWORD fErrorChar : 1;  /* Enable Err Replacement          */
	DWORD fNull : 1;       /* Enable Null stripping           */
	DWORD fRtsControl : 2;  /* Rts Flow control                */
	DWORD fAbortOnError : 1; /* Abort all reads and writes on Error */
	DWORD fDummy2 : 17;     /* Reserved                        */
	WORD wReserved;       /* Not currently used              */
	WORD XonLim;          /* Transmit X-ON threshold         */
	WORD XoffLim;         /* Transmit X-OFF threshold        */
	BYTE ByteSize;        /* Number of bits/byte, 4-8        */
	BYTE Parity;          /* 0-4=None,Odd,Even,Mark,Space    */
	BYTE StopBits;        /* 0,1,2 = 1, 1.5, 2               */
	char XonChar;         /* Tx and Rx X-ON character        */
	char XoffChar;        /* Tx and Rx X-OFF character       */
	char ErrorChar;       /* Error replacement char          */
	char EofChar;         /* End of Input character          */
	char EvtChar;         /* Received Event character        */
	WORD wReserved1;      /* Fill for now.                   */
} DCB, * LPDCB;



typedef struct _UN_COM_STATE
{
	int v18; // [rsp+70h] [rbp+17h] BYREF
	int v19; // [rsp+74h] [rbp+1Bh]
	WORD v20; // [rsp+78h] [rbp+1Fh]
	WORD v21; // [rsp+7Ch] [rbp+23h]
	WORD v22; // [rsp+78h] [rbp+1Fh]
	WORD v23; // [rsp+7Ch] [rbp+23h]
}UN_COM_STATE;


#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif // DEBUG


HANDLE hFileCom = 0;




BOOL  GetCommState(HANDLE hFile, LPDCB lpDCB)
{
	HANDLE EventA; // rdi
	NTSTATUS Status; // esi
	__int64 v7; // rdx
	__int64 v8; // r8
	int v9; // ecx
	int v10; // eax
	int v11; // eax
	int v12; // eax
	int v13; // eax
	char v14[4]; // [rsp+50h] [rbp-9h] BYREF
	char v15[8]; // [rsp+54h] [rbp-5h] BYREF
	DWORD OutputBuffer; // [rsp+5Ch] [rbp+3h] BYREF
	struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+60h] [rbp+7h] BYREF

	UN_COM_STATE UnState = { 0 };
	//int v18; // [rsp+70h] [rbp+17h] BYREF
	//int v19; // [rsp+74h] [rbp+1Bh]
	//WORD v20; // [rsp+78h] [rbp+1Fh]
	//WORD v21; // [rsp+7Ch] [rbp+23h]


	//sizeof(UnState)

	*(DWORD64*)&lpDCB->BaudRate = 0i64;
	*(DWORD64*)&lpDCB->wReserved = 0i64;
	*(DWORD64*)&lpDCB->StopBits = 0i64;
	*((DWORD*)lpDCB + 2) |= 1u;
	lpDCB->DCBlength = 28;


	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B0050u, 0i64, 0, &OutputBuffer, 4u);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}
	lpDCB->BaudRate = OutputBuffer;
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B0054u, 0i64, 0, v14, 3u);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}
	lpDCB->Parity = v14[1];
	lpDCB->ByteSize = v14[2];
	lpDCB->StopBits = v14[0];
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B0058u, 0i64, 0, v15, 6u);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}
	lpDCB->XonChar = v15[4];
	lpDCB->XoffChar = v15[5];
	lpDCB->ErrorChar = v15[1];
	lpDCB->EofChar = v15[0];
	lpDCB->EvtChar = v15[3];
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B0060u, 0i64, 0, &UnState, 0x10u);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}

	v9 = UnState.v18;
	if ((UnState.v18 & 8) != 0)
		*((DWORD*)lpDCB + 2) |= 4u;
	if ((v9 & 0x10) != 0)
		*((DWORD*)lpDCB + 2) |= 8u;
	v10 = UnState.v19;
	if ((UnState.v19 & 1) != 0)
		*((DWORD*)lpDCB + 2) |= 0x100u;
	if ((v10 & 2) != 0)
		*((DWORD*)lpDCB + 2) |= 0x200u;
	if ((v10 & 8) != 0)
		*((DWORD*)lpDCB + 2) |= 0x800u;
	if ((v10 & 4) != 0)
		*((DWORD*)lpDCB + 2) |= 0x400u;
	if (v10 < 0)
		*((DWORD*)lpDCB + 2) |= 0x80u;
	if ((v9 & 0x80000000) != 0)
		*((DWORD*)lpDCB + 2) |= 0x4000u;
	v11 = v10 & 0xC0;
	if (v11)
	{
		v12 = v11 - 64;
		if (v12)
		{
			v13 = v12 - 64;
			if (v13)
			{
				if (v13 == 64)
					*((DWORD*)lpDCB + 2) |= 0x3000u;
			}
			else
			{
				*((DWORD*)lpDCB + 2) &= ~0x1000u;
				*((DWORD*)lpDCB + 2) |= 0x2000u;
			}
		}
		else
		{
			*((DWORD*)lpDCB + 2) &= ~0x2000u;
			*((DWORD*)lpDCB + 2) |= 0x1000u;
		}
	}
	else
	{
		*((DWORD*)lpDCB + 2) &= 0xFFFFCFFF;
	}
	if ((v9 & 3) != 0)
	{
		if ((v9 & 3) == 1)
		{
			*((DWORD*)lpDCB + 2) &= ~0x20u;
			*((DWORD*)lpDCB + 2) |= 0x10u;
		}
		else if ((v9 & 3) == 2)
		{
			*((DWORD*)lpDCB + 2) &= ~0x10u;
			*((DWORD*)lpDCB + 2) |= 0x20u;
		}
	}
	else
	{
		*((DWORD*)lpDCB + 2) &= 0xFFFFFFCF;
	}
	*((DWORD*)lpDCB + 2) &= ~0x40u;
	*((DWORD*)lpDCB + 2) |= v9 & 0x40;
	lpDCB->XonLim = UnState.v20;
	lpDCB->XoffLim = UnState.v21;
	return 1;
}

BOOL  EscapeCommFunction(HANDLE hFile, DWORD dwFunc)
{
	DWORD v3; // edx
	DWORD v4; // edx
	DWORD v5; // edx
	DWORD v6; // edx
	DWORD v7; // edx
	DWORD v8; // edx
	DWORD v9; // edx
	DWORD v10; // edx
	ULONG IoControlCode; // ebx
	HANDLE EventA; // rdi
	NTSTATUS Status; // ebx
	__int64 v15; // rdx
	__int64 v16; // r8
	struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+50h] [rbp-18h] BYREF

	v3 = dwFunc - 1;
	if (v3)
	{
		v4 = v3 - 1;
		if (v4)
		{
			v5 = v4 - 1;
			if (v5)
			{
				v6 = v5 - 1;
				if (v6)
				{
					v7 = v6 - 1;
					if (v7)
					{
						v8 = v7 - 1;
						if (v8)
						{
							v9 = v8 - 1;
							if (v9)
							{
								v10 = v9 - 1;
								if (v10)
								{
									if (v10 != 1)
									{
										return 0;
									}
									IoControlCode = 1769492;
								}
								else
								{
									IoControlCode = 1769488;
								}
							}
							else
							{
								IoControlCode = 1769516;
							}
						}
						else
						{
							IoControlCode = 1769512;
						}
					}
					else
					{
						IoControlCode = 1769508;
					}
				}
				else
				{
					IoControlCode = 1769524;
				}
			}
			else
			{
				IoControlCode = 1769520;
			}
		}
		else
		{
			IoControlCode = 1769532;
		}
	}
	else
	{
		IoControlCode = 1769528;
	}
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, IoControlCode, 0i64, 0, 0i64, 0);
	if (NT_SUCCESS(Status))
	{
		return TRUE;
	}
	return FALSE;
}

#define _DWORD uint32_t
#define _QWORD uint64_t


//#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
//#define WORDn(x, n)   (*((_WORD*)&(x)+n))
#define DWORDn(x, n)  (*((_DWORD*)&(x)+n))

BOOL  SetCommState(HANDLE hFile, LPDCB lpDCB)
{
	HANDLE EventA; // rax
	void* v5; // rbx
	NTSTATUS Status; // esi
	__int64 v7; // rdx
	__int64 v8; // r8
	__int64 v9; // rcx
	unsigned int v11; // ecx
	unsigned int v12; // eax
	int v13; // edx
	int v14; // edx
	int v15; // edx
	int v16; // edx
	int v17; // ecx
	DWORD v18; // edx
	int v19; // eax
	DWORD v20; // edx
	void* v21; // rcx
	char v22[4]; // [rsp+50h] [rbp-29h] BYREF
	char EofChar; // [rsp+54h] [rbp-25h] BYREF
	char ErrorChar; // [rsp+55h] [rbp-24h]
	char v25; // [rsp+56h] [rbp-23h]
	char EvtChar; // [rsp+57h] [rbp-22h]
	char XonChar; // [rsp+58h] [rbp-21h]
	char XoffChar; // [rsp+59h] [rbp-20h]
	DWORD InputBuffer; // [rsp+5Ch] [rbp-1Dh] BYREF
	struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+60h] [rbp-19h] BYREF
	DWORD v31[4] = { 0 }; // [rsp+70h] [rbp-9h] BYREF
	//DWORD64 v31_2;
	struct _DCB DCB; // [rsp+80h] [rbp+7h] BYREF

	//v31 = 0i64;
	if (!GetCommState(hFile, &DCB))
		return 0;


	InputBuffer = lpDCB->BaudRate;
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B0004u, &InputBuffer, 4u, 0i64, 0);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}

	v11 = *((DWORD*)lpDCB + 2);
	v22[0] = lpDCB->StopBits;
	v22[1] = lpDCB->Parity;
	v22[2] = lpDCB->ByteSize;
	InputBuffer = lpDCB->BaudRate;
	XonChar = lpDCB->XonChar;
	XoffChar = lpDCB->XoffChar;
	ErrorChar = lpDCB->ErrorChar;
	v25 = ErrorChar;
	EofChar = lpDCB->EofChar;
	EvtChar = lpDCB->EvtChar;
	v12 = *((DWORD*)&(v31)+1) & 0xFFFFFF3F;
	//v12 = DWORD1(v31) & 0xFFFFFF3F;

	*((DWORD*)&(v31)+1) &= 0xFFFFFF3F;
	//DWORD1(v31) &= 0xFFFFFF3F;
	v13 = (v11 >> 12) & 3;
	if (v13)
	{
		v14 = v13 - 1;
		if (v14)
		{
			v15 = v14 - 1;
			if (v15)
			{
				if (v15 != 1)
				{
				LABEL_22:
					SetCommState(hFile, &DCB);
					return 0;
				}
				v12 |= 0xC0u;
			}
			else
			{
				v12 |= 0x80u;
			}
		}
		else
		{
			v12 |= 0x40u;
		}
		*((DWORD*)&(v31)+1) = v12;
	}
	v16 = v31[0] & 0xFFFFFFFC;

	*((DWORD*)&(v31)) = v31[0] & 0xFFFFFFFC;
	//LODWORD(v31) = v31 & 0xFFFFFFFC;
	if (((v11 >> 4) & 3) != 0)
	{
		if (((v11 >> 4) & 3) == 1)
		{
			v16 |= 1u;
		}
		else
		{
			if (((v11 >> 4) & 3) != 2)
				goto LABEL_22;
			v16 |= 2u;
		}
		*((DWORD*)&(v31)) = v16;
		//LODWORD(v31) = v16;
	}
	if ((v11 & 0x40) != 0)
	{
		v16 |= 0x40u;
		//LODWORD(v31) = v16;
		*((DWORD*)&(v31)) = v16;
	}
	if ((v11 & 4) != 0)
	{
		v16 |= 8u;
		//LODWORD(v31) = v16;
		*((DWORD*)&(v31)) = v16;
	}
	if ((v11 & 8) != 0)
	{
		v16 |= 0x10u;
		//LODWORD(v31) = v16;
		*((DWORD*)&(v31)) = v16;
	}
	if ((v11 & 0x100) != 0)
	{
		v12 |= 1u;
		//DWORD1(v31) = v12;
		*((DWORD*)&(v31)) = v12;
	}
	if ((v11 & 0x200) != 0)
	{
		v12 |= 2u;
		//DWORD1(v31) = v12;
		*((DWORD*)&(v31)) = v12;
	}
	if ((v11 & 0x800) != 0)
	{
		v12 |= 8u;
		//DWORD1(v31) = v12;
		*((DWORD*)&(v31)) = v12;
	}
	if ((v11 & 0x400) != 0)
	{
		v12 |= 4u;
		//DWORD1(v31) = v12;
		*(DWORD*)&(v31) = v12;
	}
	if ((v11 & 0x80u) != 0) {
		//DWORD1(v31) = v12 | 0x80000000;
		*((DWORD*)&(v31)+1) = v12 | 0x80000000;
	}

	if ((v11 & 0x4000) != 0) {
		//LODWORD(v31) = v16 | 0x80000000;
		*((DWORD*)&(v31)) = v16 | 0x80000000;
	}

	v17 = v11 & 0x3000;
	if (v17 == 4096)
	{
		v18 = 3;
	}
	else
	{
		if (v17)
			goto LABEL_49;
		v18 = 4;
	}
	EscapeCommFunction(hFile, v18);
LABEL_49:
	v19 = *((DWORD*)lpDCB + 2) & 0x30;
	if (v19 == 16)
	{
		v20 = 5;
	LABEL_53:
		EscapeCommFunction(hFile, v20);
		goto LABEL_54;
	}
	if (!v19)
	{
		v20 = 6;
		goto LABEL_53;
	}
LABEL_54:
	/*DWORD2(v31)*/ *((DWORD*)&(v31)+2) = lpDCB->XonLim;
	/*HIDWORD(v31)*/ *((DWORD*)&(v31)+3) = lpDCB->XoffLim;
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B000Cu, v22, 3u, 0i64, 0);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B005Cu, &EofChar, 6u, 0i64, 0);
	if (!NT_SUCCESS(Status)) {
		SetCommState(hFile, &DCB);
		return FALSE;
	}
	Status = NtDeviceIoControlFile(hFile, 0, 0i64, 0i64, &IoStatusBlock, 0x1B0064u, &v31, 0x10u, 0i64, 0);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}
	return 1;
}






hBufferFile  g_hBufferFile = 0;

extern VOID wSleepNs(LONG msec);

void server_thread_com(void* nothing) {

	LOG_DEBUG("进入信息等待环节\n");
	char* Buffer = ExAllocatePoolWithTag(PagedPool, 0x8000, 'Tag');
	NTSTATUS status = STATUS_SUCCESS;
	while (1)
	{

	//	STATUS_SUCCESS



		//ZwReadFile(hFileCom,0,0,0)

		IO_STATUS_BLOCK Io_Blok;
		LARGE_INTEGER Large;
		Large.QuadPart = 0;
	    status = NtReadFile(hFileCom, NULL, NULL, NULL, &Io_Blok,
			Buffer, 0x8000, &Large, 0);
		if (status == STATUS_PENDING){
			LOG_DEBUG("Handle  %08X   %08X\n", Io_Blok.Information, status);
			wSleepNs(1);
			continue;
		}
		if (NT_SUCCESS(status)){
			LOG_DEBUG("Handle  %d   %08X\n", Io_Blok.Information, status);
			g_hBufferFile(hFileCom, Buffer,  (int)Io_Blok.Information);
		}
		else
		{
			LOG_DEBUG("Handle  %08X\n", status);
		}
	}
	ExFreePoolWithTag(Buffer, 'Tag');
}






BOOL IniComMsg(hBufferFile _CALLBACK_HANDLE) {

	UNICODE_STRING ComName;
	RtlInitUnicodeString(&ComName, L"\\??\\COM3");
	IO_STATUS_BLOCK Io_Blok;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &ComName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status = ZwCreateFile(&hFileCom,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&ObjectAttributes,
		&Io_Blok,
		0,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0
	);

	//STATUS_SUCCESS
	if (NT_SUCCESS(status))
	{
		LOG_DEBUG("打开串口1 成功 \n");
		//ZwClose(hFile);


		DCB dcb;

		if (!GetCommState(hFileCom, &dcb))
		{
			LOG_DEBUG("获取串口信息失败\n");
			ZwClose(hFileCom);
			return FALSE;
		}

		dcb.DCBlength = sizeof(DCB);
		dcb.BaudRate = CBR_115200; // 运行时波特率
		dcb.Parity = NOPARITY;
		dcb.ByteSize = 8;
		dcb.StopBits = ONESTOPBIT;

		if (!SetCommState(hFileCom, &dcb))
		{
			LOG_DEBUG("设置串口信息失败\n");
			ZwClose(hFileCom);
			return FALSE;
		}
		g_hBufferFile = _CALLBACK_HANDLE;
		HANDLE thread_handle;
		PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_thread_com, 0);
		//ZwClose(hFileCom);
		return TRUE;

	}
	else
	{
		LOG_DEBUG("打开串口1 失败  %08X \n", status);
	}
	return FALSE;
}