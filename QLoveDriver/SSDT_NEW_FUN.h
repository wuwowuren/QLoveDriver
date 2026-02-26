#pragma once

#include "SSDT_HOOK.h"

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>
#include<ntstrsafe.h>

#include <windef.h>
#include "KSandBox.h"

typedef struct _tPOINT
{
	int x;
	int y;
}BRPOINT, * LPBRPOINT;

DECLARE_HANDLE(HRAWINPUT);

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned int        UINT;
typedef unsigned int* PUINT;
typedef UINT_PTR            WPARAM;


#define AVL_ADD 0
#define AVL_DEL 1
#define AVL_MOD 2
#define AVL_GET 3
#define AVL_LOCK 4
#define AVL_UNLOCK 5

typedef struct _AVL_INFO {
	RTL_AVL_TABLE AVL_Table;
	KSPIN_LOCK Lock;
}AVL_INFO, * PAVL_INFO;



typedef struct _MEMORY_INFO_USER {
	AVL_INFO AvlInfo;
	PVOID Object;
	HANDLE hID;
}MEMORY_INFO_USER, * PMEMORY_INFO_USER;


typedef struct tagRAWHID {
	DWORD dwSizeHid;
	DWORD dwCount;
	BYTE  bRawData[1];
} RAWHID, * PRAWHID, * LPRAWHID;

typedef struct tagRAWMOUSE {
	USHORT usFlags;
	union {
		ULONG ulButtons;
		struct {
			USHORT usButtonFlags;
			USHORT usButtonData;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	ULONG  ulRawButtons;
	LONG   lLastX;
	LONG   lLastY;
	ULONG  ulExtraInformation;
} RAWMOUSE, * PRAWMOUSE, * LPRAWMOUSE;

typedef struct tagRAWKEYBOARD {
	USHORT MakeCode;
	USHORT Flags;
	USHORT Reserved;
	USHORT VKey;
	UINT   Message;
	ULONG  ExtraInformation;
} RAWKEYBOARD, * PRAWKEYBOARD, * LPRAWKEYBOARD;

typedef struct tagRAWINPUTHEADER {
	DWORD  dwType;
	DWORD  dwSize;
	HANDLE hDevice;
	WPARAM wParam;
} RAWINPUTHEADER, * PRAWINPUTHEADER, * LPRAWINPUTHEADER;

typedef struct tagRAWINPUT {
	RAWINPUTHEADER header;
	union {
		RAWMOUSE    mouse;
		RAWKEYBOARD keyboard;
		RAWHID      hid;
	} data;
} RAWINPUT, * PRAWINPUT, * LPRAWINPUT;


#define CCHDEVICENAME 32
#define CCHFORMNAME 32
typedef struct _devicemodeW {
	WCHAR  dmDeviceName[CCHDEVICENAME];
	WORD dmSpecVersion;
	WORD dmDriverVersion;
	WORD dmSize;
	WORD dmDriverExtra;
	DWORD dmFields;
	union {
		/* printer only fields */
		struct {
			short dmOrientation;
			short dmPaperSize;
			short dmPaperLength;
			short dmPaperWidth;
			short dmScale;
			short dmCopies;
			short dmDefaultSource;
			short dmPrintQuality;
		} DUMMYSTRUCTNAME;
		/* display only fields */
		struct {
			POINTL dmPosition;
			DWORD  dmDisplayOrientation;
			DWORD  dmDisplayFixedOutput;
		} DUMMYSTRUCTNAME2;
	} DUMMYUNIONNAME;
	short dmColor;
	short dmDuplex;
	short dmYResolution;
	short dmTTOption;
	short dmCollate;
	WCHAR  dmFormName[CCHFORMNAME];
	WORD   dmLogPixels;
	DWORD  dmBitsPerPel;
	DWORD  dmPelsWidth;
	DWORD  dmPelsHeight;
	union {
		DWORD  dmDisplayFlags;
		DWORD  dmNup;
	} DUMMYUNIONNAME2;
	DWORD  dmDisplayFrequency;
#if(WINVER >= 0x0400)
	DWORD  dmICMMethod;
	DWORD  dmICMIntent;
	DWORD  dmMediaType;
	DWORD  dmDitherType;
	DWORD  dmReserved1;
	DWORD  dmReserved2;
#if (WINVER >= 0x0500) || (_WIN32_WINNT >= _WIN32_WINNT_NT4)
	DWORD  dmPanningWidth;
	DWORD  dmPanningHeight;
#endif
#endif /* WINVER >= 0x0400 */
}DEVMODEW, * PDEVMODEW, * NPDEVMODEW, * LPDEVMODEW;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;


typedef
_Function_class_(KRUNDOWN_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KRUNDOWN_ROUTINE(
	_In_ struct _KAPC* Apc
);
typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

typedef
_Function_class_(KNORMAL_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KNORMAL_ROUTINE(
	_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;
typedef
_Function_class_(KKERNEL_ROUTINE)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(APC_LEVEL)
_IRQL_requires_(APC_LEVEL)
_IRQL_requires_same_
VOID
KKERNEL_ROUTINE(
	_In_ struct _KAPC* Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;

NTKERNELAPI
_IRQL_requires_same_
_When_(Environment != OriginalApcEnvironment, __drv_reportError("Caution: "
	"Using an APC environment other than the original environment can lead to "
	"a system bugcheck if the target thread is attached to a process with APCs "
	"disabled. APC environments should be used with care."))
	VOID
	KeInitializeApc(
		_Out_ PRKAPC Apc,
		_In_ PRKTHREAD Thread,
		_In_ KAPC_ENVIRONMENT Environment,
		_In_ PKKERNEL_ROUTINE KernelRoutine,
		_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
		_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
		_In_opt_ KPROCESSOR_MODE ProcessorMode,
		_In_opt_ PVOID NormalContext
	);

NTKERNELAPI
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
BOOLEAN
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

BOOLEAN AddForeHwnd(HANDLE dwID, HANDLE hwnd);

BOOLEAN AddFixPoint(HANDLE dwID, BRPOINT p, int Type);

BOOLEAN StopFixPoint(HANDLE dwID);

BOOLEAN AddKeyBoard(HANDLE dwID, int p, int Type);

BOOLEAN StopKeyBoard(HANDLE dwID, int Type);

BOOLEAN AddInputData(HANDLE dwID, RAWINPUT* _Raw);

//void INI_LIST_ALL();
PVOID GetModNodePtr(uintptr_t ModBase, LPCSTR pstr, DWORD* pSize);

void __fastcall CALL_BACK(unsigned int Index, void** pAddress);

VOID HOOK_BEGIN();


BOOLEAN FilterFileName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);

BOOLEAN FilterMutexName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);

BOOLEAN FilterEventName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);

BOOLEAN FilterSectionName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);

BOOLEAN FilterProcessName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);

//BOOLEAN SandBoxFilter(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);
PVOID AVL_LOCK_CHANGE_VOID(DWORD flags, PAVL_INFO Avl, PVOID pInfo, DWORD nSize);


void GetBasePTE();

BOOLEAN  SetRawInput(HRAWINPUT hRawInput);


//NTKERNELAPI
//PVOID MmMapIoSpace(
//	 PHYSICAL_ADDRESS    PhysicalAddress,
//	 SIZE_T              NumberOfBytes,
//	 MEMORY_CACHING_TYPE CacheType
//);
//// MmCached
//NTKERNELAPI
//void MmUnmapIoSpace(
//	 PVOID  BaseAddress,
//	 SIZE_T NumberOfBytes
//);

PVOID  DetourCopyInstruction( PVOID pDst,
		 PVOID* ppDstPool,
		 PVOID pSrc,
		 PVOID* ppTarget,
		 LONG* plExtra);

PVOID  LoadMemoryToUser(PMDL* pMdl, PVOID addr, DWORD nSize, KPROCESSOR_MODE Mode, ULONG Protect);



typedef struct _MEM_LIST_PID {
	LIST_ENTRY Link;
	HANDLE dwPID;
	PVOID addr;
	size_t size;
	BOOLEAN IsUse;
	time_t Time;
	DWORD64 _FindWindowW;
	DWORD64 _GetWindwRect;
	DWORD64 _MouseEvent;
	DWORD64 _KeybdEvent;
	DWORD64 _PeekMessageW;
	DWORD64 _ClientToScreen;
}MEM_LIST_PID, * PMEM_LIST_PID;

//DECLARE_HANDLE(HWND);

typedef DWORD(*_Win32k_NtUserGetThreadState)(UINT nInputs);

typedef DWORD64(*_Win32k_NtUserSendInput)(UINT nInputs, void* pInput, INT cbSize);

typedef DWORD(*_Win32k_NtUserCallHwndLock)(HWND Hwnd, DWORD Flags);

typedef void (*_Win32k_NtUserCallTwoParam)(void* Val, DWORD nInputs, DWORD Flags);

typedef DWORD64 (*_Win32k_NtUserCallOneParam)(HWND Hwnd, DWORD Flags);

typedef void  (*_Win32k_NtUserCloseClipboard)();

typedef BOOL  (*_Win32k_NtUserOpenClipboard)(HWND hWnd, PULONG pFlags);

typedef HANDLE(*_Win32k_NtUserSetClipboardData)(UINT Flags, HANDLE hMem, PULONG pFlags);

typedef HANDLE(*_Win32k_NtUserGetClipboardData)(UINT Flags, PULONG pFlags);

typedef void(*_Win32k_NtUserEmptyClipboard)();

typedef HANDLE(*_Win32k_NtUserConvertMemHandle)(PVOID pData, SIZE_T cbData);

typedef NTSTATUS(*_Win32k_NtUserCreateLocalMemHandle)(HANDLE hMem,
	PVOID pData,
	DWORD cbData,
	DWORD* pcbData);


typedef NTSTATUS(*_Win32k_NtUserEnumDisplaySettings)(PUNICODE_STRING lpszDeviceName, DWORD iModeNum, 
	DEVMODEW* lpDevMode, DWORD dwFlags);

typedef HDC(*_win32k_NtUserGetDC)(HWND hwnd);

typedef HBITMAP(*_win32k_NtGdiCreateCompatibleBitmap)(HDC hDC, int cx, int cy);

typedef HDC(*_win32k_NtGdiCreateCompatibleDC)(HDC hdc);

typedef NTSTATUS(*_win32k_NtGdiBitBlt)(HDC hDC, int x, int y, int cx, int cy, HDC hDcSrc, int x1, int y1, DWORD Rop, DWORD64 Flags, DWORD64 Zero);

typedef HGDIOBJ(*_win32k_NtGdiSelectBitmap)(HDC hdc, HGDIOBJ h);

typedef NTSTATUS(*_win32k_NtUserReleaseDC)(HDC hdc);

typedef int(*_win32k_NtGdiExtGetObjectW)(HANDLE h, int c, LPVOID pv);

typedef LONG(*_win32k_NtGdiGetBitmapBits)(HBITMAP hbit, LONG cb, LPVOID lpvBits);

             







#define  LPARAM LONG_PTR

#define  WPARAM LONG_PTR

typedef  DWORD(*_Win32k_NtUserPostMessage)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef LONG_PTR(*_Win32k_NtUserSetWindowLongPtr)(HWND hWnd, int nIndex, LONG_PTR dwNewLong, DWORD Flags);


 // Flags 0 ProcessID  2 ThreadID
typedef DWORD(*_Win32k_NtUserQueryWindow)(HWND Hwnd, DWORD Flags);

//NtUserCallTwoParam

typedef NTSTATUS(*_Win32k_NtUserBuildHwndList)(
	UINT hDesktop,//0
	UINT hwndParent,//0
	BOOLEAN bChildren,//0
	ULONG dwThreadId, //1
	ULONG lParam, //0
	UINT* pWnd,
	ULONG* pBufSize);

typedef HWND(*_Win32k_NtUserFindWindowEx)(
	IN UINT hwndParent,
	IN UINT hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType);



//NtUserGetForegroundWindow


typedef HWND(*_Win32k_NtUserGetForegroundWindow)();

typedef UINT(*_User32_FindWindowW)(LPCWSTR lpClassName, LPCWSTR lpWindowName);






// Win32kBase

//

typedef DWORD64(*_Win32k_ValidateHwnd)(HWND Hwnd);

//typedef DWORD64(*_Win32k_ValidateHwnd)(DWORD64 Object);
//
//typedef DWORD64(*_Win32k_ValidateHwnd)(DWORD64 Object);


typedef struct tagRECTK
{
	LONG    left;
	LONG    top;
	LONG    right;
	LONG    bottom;
} RECTK,* LPRECTK;

typedef struct tagMSGK{
	HWND hWnd;
	UINT Msg;
	WPARAM wParam;
	LPARAM lParam;
} MSGK, * LPMSGK;

UINT ClientToScreen_User(HWND Hwnd, LPPOINT lpPoint);

UINT  GetWindowRect_User(HWND Hwnd, LPRECTK lpRect);
HWND  FindWindowW_User(PUNICODE_STRING lpClassName, PUNICODE_STRING lpWindowName);
UINT  ClientToScreen_Kernel(HWND Hwnd, LPPOINT lpPoint);
HWND  FindWindowW(PUNICODE_STRING lpClassName, PUNICODE_STRING lpWindowName);
HWND  GetForegroundWindow();
UINT  SetForegroundWindow(HWND hwnd);

UINT PrintPicture(POINT StartP, DWORD with, DWORD Height, LPVOID Ptr);



#define MOUSEEVENTF_MOVE        0x0001 /* mouse move */
#define MOUSEEVENTF_LEFTDOWN    0x0002 /* left button down */
#define MOUSEEVENTF_LEFTUP      0x0004 /* left button up */
#define MOUSEEVENTF_RIGHTDOWN   0x0008 /* right button down */
#define MOUSEEVENTF_RIGHTUP     0x0010 /* right button up */
#define MOUSEEVENTF_MIDDLEDOWN  0x0020 /* middle button down */
#define MOUSEEVENTF_MIDDLEUP    0x0040 /* middle button up */
#define MOUSEEVENTF_XDOWN       0x0080 /* x button down */
#define MOUSEEVENTF_XUP         0x0100 /* x button down */
#define MOUSEEVENTF_WHEEL                0x0800 /* wheel button rolled */
#if (_WIN32_WINNT >= 0x0600)
#define MOUSEEVENTF_HWHEEL              0x01000 /* hwheel button rolled */
#endif
#if(WINVER >= 0x0600)
#define MOUSEEVENTF_MOVE_NOCOALESCE      0x2000 /* do not coalesce mouse moves */
#endif /* WINVER >= 0x0600 */
#define MOUSEEVENTF_VIRTUALDESK          0x4000 /* map to entire virtual desktop */
#define MOUSEEVENTF_ABSOLUTE             0x8000 /* absolute move */





#pragma pack(push,8)
typedef struct _KETBD_EVENT
{
	BYTE bVk;
	BYTE bScan;
	DWORD dwFlags;
	ULONG_PTR dwExtraInfo;
}KETBD_EVENT;

typedef struct _MOUSE_EVENT
{
	DWORD dwFlags;
	DWORD dx;
	DWORD dy;
	DWORD dwData;
	ULONG_PTR dwExtraInfo;
}MOUSE_EVENT;




#pragma pack(pop)




//void  mouse_event2(MOUSE_EVENT* pMouseEvent);

void  mouse_event(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo);

void  keybd_event(BYTE bVk, BYTE bScan, DWORD dwFlags, ULONG_PTR dwExtraInfo);

int GetClipboardData(HWND Hwnd, wchar_t* Ptr, PULONG pSize);

BOOL SetClipboardData(HWND Hwnd, wchar_t* Ptr, ULONG nSize);

BOOL EmptyClipboardData();

int PostMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);


NTSTATUS EnumDisplaySettingsExW(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode, DWORD dwFlags);



LONG_PTR _Kernel_SetWindowLongPtr(HWND hWnd, int nIndex, LONG_PTR dwNewLong, DWORD64 Flags);










// 

BOOLEAN FindZeroMemory(int PageSize, PVOID* hMod, PVOID* NewMod);
