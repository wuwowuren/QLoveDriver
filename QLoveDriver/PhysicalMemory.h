#pragma once

#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	


#define MI_MAXIMUM_PAGEFILE_SIZE (((UINT64)4 * 1024 * 1024 * 1024 - 1) * PAGE_SIZE)

#define MI_PTE_LOOKUP_NEEDED ((ULONG64)0xffffffff)



#define _HARDWARE_PTE_WORKING_SET_BITS  11

typedef struct _HARDWARE_PTE {
    ULONG64 Valid : 1;
    ULONG64 Write : 1;                // UP version
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;          // software field
    ULONG64 Prototype : 1;            // software field
    ULONG64 reserved0 : 1;            // software field
    ULONG64 PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
    ULONG64 SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} HARDWARE_PTE, * PHARDWARE_PTE;

#define PTE_PER_PAGE_BITS 10 
typedef struct _MMPTE_SOFTWARE {
    ULONGLONG Valid : 1;
    ULONGLONG PageFileLow : 4;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG UsedPageTableEntries : PTE_PER_PAGE_BITS;
    ULONGLONG Reserved : 20 - PTE_PER_PAGE_BITS;
    ULONGLONG PageFileHigh : 32;
} MMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION {
    ULONGLONG Valid : 1;
    ULONGLONG Write : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG PageFrameNumber : 28;
    ULONGLONG Unused : 24;
} MMPTE_TRANSITION;

typedef struct _MMPTE_PROTOTYPE {
    ULONGLONG Valid : 1;
    ULONGLONG Unused0 : 7;
    ULONGLONG ReadOnly : 1;
    ULONGLONG Unused1 : 1;
    ULONGLONG Prototype : 1;
    ULONGLONG Protection : 5;
    LONGLONG ProtoAddress : 48;
} MMPTE_PROTOTYPE;

typedef struct _MMPTE_SUBSECTION {
    ULONGLONG Valid : 1;
    ULONGLONG Unused0 : 4;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Unused1 : 5;
    LONGLONG SubsectionAddress : 48;
} MMPTE_SUBSECTION;

typedef struct _MMPTE_LIST {
    ULONGLONG Valid : 1;
    ULONGLONG OneEntry : 1;
    ULONGLONG filler0 : 3;

    //
    // Note the Prototype bit must not be used for lists like freed nonpaged
    // pool because lookaside pops can legitimately reference bogus addresses
    // (since the pop is unsynchronized) and the fault handler must be able to
    // distinguish lists from protos so a retry status can be returned (vs a
    // fatal bugcheck).
    //
    // The same caveat applies to both the Transition and the Protection
    // fields as they are similarly examined in the fault handler and would
    // be misinterpreted if ever nonzero in the freed nonpaged pool chains.
    //

    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;        // MUST BE ZERO as per above comment.
    ULONGLONG Transition : 1;

    ULONGLONG filler1 : 20;
    ULONGLONG NextEntry : 32;
} MMPTE_LIST;

typedef struct _MMPTE_HIGHLOW {
    ULONG LowPart;
    ULONG HighPart;
} MMPTE_HIGHLOW;


typedef struct _MMPTE_HARDWARE_LARGEPAGE {
    ULONGLONG Valid : 1;//1
    ULONGLONG Write : 1;//2
    ULONGLONG Owner : 1;//4
    ULONGLONG WriteThrough : 1;//8
    ULONGLONG CacheDisable : 1;//0x10
    ULONGLONG Accessed : 1;//0x20
    ULONGLONG Dirty : 1;//0x40
    ULONGLONG LargePage : 1;//0x80
    ULONGLONG Global : 1;//0x100
    ULONGLONG CopyOnWrite : 1; // software field//0x200
    ULONGLONG Prototype : 1;   // software field // 0x400
    ULONGLONG reserved0 : 1;   // software field //0x800
    ULONGLONG PAT : 1;
    ULONGLONG reserved1 : 8;   // software field
    ULONGLONG PageFrameNumber : 19;
    ULONGLONG reserved2 : 24;   // software field
} MMPTE_HARDWARE_LARGEPAGE, * PMMPTE_HARDWARE_LARGEPAGE;

//
// A Page Table Entry on AMD64 has the following definition.
// Note the MP version is to avoid stalls when flushing TBs across processors.
//

//
// Uniprocessor version.
//

typedef struct _MMPTE_HARDWARE {
    ULONGLONG Valid : 1;  // 1
#if defined(NT_UP)
    ULONGLONG Write : 1;        // UP version
#else
    ULONGLONG Writable : 1;        // changed for MP version // 2
#endif
    ULONGLONG Owner : 1;   // 4
    ULONGLONG WriteThrough : 1; // 8
    ULONGLONG CacheDisable : 1; //0x10
    ULONGLONG Accessed : 1; //0x20
    ULONGLONG Dirty : 1; // 0x40
    ULONGLONG LargePage : 1; // 0x80
    ULONGLONG Global : 1; //0x100
    ULONGLONG CopyOnWrite : 1; // software field //0x200
    ULONGLONG Prototype : 1;   // software field //0x400
#if defined(NT_UP)
    ULONGLONG reserved0 : 1;  // software field
#else
    ULONGLONG Write : 1;       // software field - MP change //0x800
#endif
    ULONGLONG PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
    ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

#if defined(NT_UP)
#define HARDWARE_PTE_DIRTY_MASK     0x40
#else
#define HARDWARE_PTE_DIRTY_MASK     0x42
#endif

#define MI_PDE_MAPS_LARGE_PAGE(PDE) ((PDE)->u.Hard.LargePage == 1)

#define MI_MAKE_PDE_MAP_LARGE_PAGE(PDE) ((PDE)->u.Hard.LargePage = 1)

#define MI_GET_PAGE_FRAME_FROM_PTE(PTE) ((PTE)->u.Hard.PageFrameNumber)
#define MI_GET_PAGE_FRAME_FROM_TRANSITION_PTE(PTE) ((PTE)->u.Trans.PageFrameNumber)
#define MI_GET_PROTECTION_FROM_SOFT_PTE(PTE) ((ULONG)(PTE)->u.Soft.Protection)
#define MI_GET_PROTECTION_FROM_TRANSITION_PTE(PTE) ((ULONG)(PTE)->u.Trans.Protection)

typedef struct _MMPTE {
    union {
        ULONG_PTR Long;
        MMPTE_HARDWARE Hard;
        MMPTE_HARDWARE_LARGEPAGE HardLarge;
        HARDWARE_PTE Flush;
        MMPTE_PROTOTYPE Proto;
        MMPTE_SOFTWARE Soft;
        MMPTE_TRANSITION Trans;
        MMPTE_SUBSECTION Subsect;
        MMPTE_LIST List;
    } u;
} MMPTE,* PMMPTE;


#define PTE_SIZE 512


PHYSICAL_ADDRESS __stdcall wMmGetPhysicalAddress(PVOID BaseAddress, PEPROCESS eprocess);

BOOLEAN ReadPhysicalAddress(PHYSICAL_ADDRESS BaseAddress, PVOID Val, DWORD nSize);

unsigned __int64 __fastcall MiVaToPfn(unsigned __int64 a1, PEPROCESS Process);

__int64 __fastcall MI_IS_PHYSICAL_ADDRESS(unsigned __int64 a1, PEPROCESS Process);

__int64 __fastcall MI_IS_PHYSICAL_ADDRESS2(unsigned __int64 a1);

BOOLEAN ReadProcessMemoryV(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize);

BOOLEAN WriteProcessMemoryV(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize);

BOOLEAN ReadProcessMemoryEx(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize);

BOOLEAN WriteProcessMemoryEx(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize);

unsigned __int64 __fastcall MiFillPteHierarchy(unsigned __int64 a1, unsigned __int64* a2);

DWORD64 GetAddressPteHierarchy(unsigned __int64 a1, unsigned __int64* a2);

BOOL SetAddressTlb(ULONGLONG Address, ULONGLONG PageNumber, ULONGLONG referAddress);


MMPTE* GetAddressPfn(ULONGLONG Address);

//BOOL SetAddressTlb(ULONGLONG Address, ULONG PageNumber);

//BOOL SetAddressTlb(ULONGLONG Address, int PageNumber);

//BOOL VirtualSinglePAGE(PEPROCESS Process, PVOID VAddress);

DWORD64 WeGetProcessType(HANDLE PID);

DWORD64 WeSetProcessType(HANDLE PID, DWORD64 dwType);

BOOLEAN MiSingleProcessMemory(PEPROCESS Process, PVOID Poiner, SIZE_T nSize, PVOID* NewPoiner);





