



#include "defs.h"

#include "../../WRK/base/ntos/mm/mi.h"
//#include <winnt.h>

#ifndef _GDEF_H_
#define _GDEF_H_
#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include <ntimage.h>
//#include<wdm.h>

//#include <wow64apiset.h>



#pragma warning(disable:4201)
#pragma warning(disable:4214)

//#include <>

//#include <winnt.h>

//typedef struct _KLDR_DATA_TABLE_ENTRY
//{
//	LIST_ENTRY64 InLoadOrderLinks;
//	ULONG64 __Undefined1;
//	ULONG64 __Undefined2;
//	ULONG64 __Undefined3;
//	ULONG64 NonPagedDebugInfo;
//	ULONG64 DllBase;
//	ULONG64 EntryPoint;
//	ULONG SizeOfImage;
//	UNICODE_STRING FullDllName;
//	UNICODE_STRING BaseDllName;
//	ULONG   Flags;
//	USHORT  LoadCount;
//	USHORT  __Undefined5;
//	ULONG64 __Undefined6;
//	ULONG   CheckSum;
//	ULONG   __padding1;
//	ULONG   TimeDateStamp;
//	ULONG   __padding2;
//} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
//
//#define _HARDWARE_PTE_WORKING_SET_BITS  11
//
////typedef struct _MMPTE_HARDWARE {
////	ULONGLONG Valid : 1;
////	ULONGLONG Write : 1;        // UP version
////	ULONGLONG Owner : 1;
////	ULONGLONG WriteThrough : 1;
////	ULONGLONG CacheDisable : 1;
////	ULONGLONG Accessed : 1;
////	ULONGLONG Dirty : 1;
////	ULONGLONG LargePage : 1;
////	ULONGLONG Global : 1;
////	ULONGLONG CopyOnWrite : 1; // software field
////	ULONGLONG Prototype : 1;   // software field
////	ULONGLONG reserved0 : 1;  // software field
////	ULONGLONG PageFrameNumber : 28;
////	ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
////	ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
////	ULONG64 NoExecute : 1;
////} MMPTE_HARDWARE, *PMMPTE_HARDWARE;
//
//
//typedef struct _MMPTE_HARDWARE {
//	ULONGLONG Valid : 1;
//#if defined(NT_UP)
//	ULONGLONG Write : 1;        // UP version
//#else
//	ULONGLONG Writable : 1;        // changed for MP version
//#endif
//	ULONGLONG Owner : 1;
//	ULONGLONG WriteThrough : 1;
//	ULONGLONG CacheDisable : 1;
//	ULONGLONG Accessed : 1;
//	ULONGLONG Dirty : 1;
//	ULONGLONG LargePage : 1;
//	ULONGLONG Global : 1;
//	ULONGLONG CopyOnWrite : 1; // software field
//	ULONGLONG Prototype : 1;   // software field
//#if defined(NT_UP)
//	ULONGLONG reserved0 : 1;  // software field
//#else
//	ULONGLONG Write : 1;       // software field - MP change
//#endif
//	ULONGLONG PageFrameNumber : 28;
//	ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
//	ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
//	ULONG64 NoExecute : 1;
//} MMPTE_HARDWARE, *PMMPTE_HARDWARE;
//
//typedef struct _MMPTE_HARDWARE_LARGEPAGE {
//	ULONGLONG Valid : 1;
//	ULONGLONG Write : 1;
//	ULONGLONG Owner : 1;
//	ULONGLONG WriteThrough : 1;
//	ULONGLONG CacheDisable : 1;
//	ULONGLONG Accessed : 1;
//	ULONGLONG Dirty : 1;
//	ULONGLONG LargePage : 1;
//	ULONGLONG Global : 1;
//	ULONGLONG CopyOnWrite : 1; // software field
//	ULONGLONG Prototype : 1;   // software field
//	ULONGLONG reserved0 : 1;   // software field
//	ULONGLONG PAT : 1;
//	ULONGLONG reserved1 : 8;   // software field
//	ULONGLONG PageFrameNumber : 19;
//	ULONGLONG reserved2 : 24;   // software field
//} MMPTE_HARDWARE_LARGEPAGE, *PMMPTE_HARDWARE_LARGEPAGE;
//typedef struct _HARDWARE_PTE {
//	ULONG64 Valid : 1;
//	ULONG64 Write : 1;                // UP version
//	ULONG64 Owner : 1;
//	ULONG64 WriteThrough : 1;
//	ULONG64 CacheDisable : 1;
//	ULONG64 Accessed : 1;
//	ULONG64 Dirty : 1;
//	ULONG64 LargePage : 1;
//	ULONG64 Global : 1;
//	ULONG64 CopyOnWrite : 1;          // software field
//	ULONG64 Prototype : 1;            // software field
//	ULONG64 reserved0 : 1;            // software field
//	ULONG64 PageFrameNumber : 28;
//	ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
//	ULONG64 SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
//	ULONG64 NoExecute : 1;
//} HARDWARE_PTE, *PHARDWARE_PTE;
//
//#define PTE_PER_PAGE_BITS 10    // This handles the case where the page is full
//
//typedef struct _MMPTE_SOFTWARE {
//	ULONGLONG Valid : 1;
//	ULONGLONG PageFileLow : 4;
//	ULONGLONG Protection : 5;
//	ULONGLONG Prototype : 1;
//	ULONGLONG Transition : 1;
//	ULONGLONG UsedPageTableEntries : PTE_PER_PAGE_BITS;
//	ULONGLONG Reserved : 20 - PTE_PER_PAGE_BITS;
//	ULONGLONG PageFileHigh : 32;
//} MMPTE_SOFTWARE;
//
//typedef struct _MMPTE_TRANSITION {
//	ULONGLONG Valid : 1;
//	ULONGLONG Write : 1;
//	ULONGLONG Owner : 1;
//	ULONGLONG WriteThrough : 1;
//	ULONGLONG CacheDisable : 1;
//	ULONGLONG Protection : 5;
//	ULONGLONG Prototype : 1;
//	ULONGLONG Transition : 1;
//	ULONGLONG PageFrameNumber : 28;
//	ULONGLONG Unused : 24;
//} MMPTE_TRANSITION;
//
//typedef struct _MMPTE_PROTOTYPE {
//	ULONGLONG Valid : 1;
//	ULONGLONG Unused0 : 7;
//	ULONGLONG ReadOnly : 1;
//	ULONGLONG Unused1 : 1;
//	ULONGLONG Prototype : 1;
//	ULONGLONG Protection : 5;
//	LONGLONG ProtoAddress : 48;
//} MMPTE_PROTOTYPE;
//
//typedef struct _MMPTE_SUBSECTION {
//	ULONGLONG Valid : 1;
//	ULONGLONG Unused0 : 4;
//	ULONGLONG Protection : 5;
//	ULONGLONG Prototype : 1;
//	ULONGLONG Unused1 : 5;
//	LONGLONG SubsectionAddress : 48;
//} MMPTE_SUBSECTION;
//
//typedef struct _MMPTE_LIST {
//	ULONGLONG Valid : 1;
//	ULONGLONG OneEntry : 1;
//	ULONGLONG filler0 : 3;
//
//	//
//	// Note the Prototype bit must not be used for lists like freed nonpaged
//	// pool because lookaside pops can legitimately reference bogus addresses
//	// (since the pop is unsynchronized) and the fault handler must be able to
//	// distinguish lists from protos so a retry status can be returned (vs a
//	// fatal bugcheck).
//	//
//	// The same caveat applies to both the Transition and the Protection
//	// fields as they are similarly examined in the fault handler and would
//	// be misinterpreted if ever nonzero in the freed nonpaged pool chains.
//	//
//
//	ULONGLONG Protection : 5;
//	ULONGLONG Prototype : 1;        // MUST BE ZERO as per above comment.
//	ULONGLONG Transition : 1;
//
//	ULONGLONG filler1 : 20;
//	ULONGLONG NextEntry : 32;
//} MMPTE_LIST;
//
//typedef struct _MMPTE {
//	union {
//		ULONG_PTR Long;
//		MMPTE_HARDWARE Hard;
//		MMPTE_HARDWARE_LARGEPAGE HardLarge;
//		HARDWARE_PTE Flush;
//		MMPTE_PROTOTYPE Proto;
//		MMPTE_SOFTWARE Soft;
//		MMPTE_TRANSITION Trans;
//		MMPTE_SUBSECTION Subsect;
//		MMPTE_LIST List;
//	} u;
//} MMPTE;
//
//typedef MMPTE *PMMPTE;

typedef ULONG WSLE_NUMBER, *PWSLE_NUMBER;

typedef struct _MMPFNENTRY {
	USHORT Modified : 1;
	USHORT ReadInProgress : 1;
	USHORT WriteInProgress : 1;
	USHORT PrototypePte : 1;
	USHORT PageColor : 4;
	USHORT PageLocation : 3;
	USHORT RemovalRequested : 1;

	//
	// The CacheAttribute field is what the current (or last) TB attribute used.
	// This is not cleared when the frame is unmapped because in cases like
	// system PTE mappings for MDLs, we lazy flush the TB (for performance)
	// so we don't know when the final TB flush has really occurred.  To ensure
	// that we never insert a TB that would cause an overlapping condition,
	// whenever a PTE is filled with a freshly allocated frame, the filler
	// assumes responsibility for comparing the new cache attribute with the
	// last known used attribute and if they differ, the filler must flush the
	// entire TB.  KeFlushSingleTb cannot be used because we don't know
	// what virtual address(es) this physical frame was last mapped at.
	//
	// This may result in some TB overflushing in the case
	// where no system PTE was used so it would have been safe to clear the
	// attribute in the PFN, but it reusing a page with a differing attribute
	// should be a fairly rare case anyway.
	//

	USHORT CacheAttribute : 2;
	USHORT Rom : 1;
	USHORT ParityError : 1;
} MMPFNENTRY;

#define MI_PFN_PRIORITY_BITS    3

typedef struct _MMPFN {
	union {
		PFN_NUMBER Flink;
		WSLE_NUMBER WsIndex;
		PKEVENT Event;
		NTSTATUS ReadStatus;

		//
		// Note: NextStackPfn is actually used as SLIST_ENTRY, however
		// because of its alignment characteristics, using that type would
		// unnecessarily add padding to this structure.
		//

		SINGLE_LIST_ENTRY NextStackPfn;
	} u1;
	PMMPTE PteAddress;
	union {
		PFN_NUMBER Blink;

		//
		// ShareCount transitions are protected by the PFN lock.
		//

		ULONG_PTR ShareCount;
	} u2;
	union {

		//
		// ReferenceCount transitions are generally done with InterlockedXxxPfn
		// sequences, and only the 0->1 and 1->0 transitions are protected
		// by the PFN lock.  Note that a *VERY* intricate synchronization
		// scheme is being used to maximize scalability.
		//

		struct {
			USHORT ReferenceCount;
			MMPFNENTRY e1;
		};
		struct {
			USHORT ReferenceCount;
			USHORT ShortFlags;
		} e2;
	} u3;
#if defined (_WIN64)
	ULONG UsedPageTableEntries;
#endif
	union {
		MMPTE OriginalPte;
		LONG AweReferenceCount;
	};
	union {
		ULONG_PTR EntireFrame;
		struct {
#if defined (_WIN64)
			ULONG_PTR PteFrame : 57;
#else
			ULONG_PTR PteFrame : 25;
#endif
			ULONG_PTR InPageError : 1;
			ULONG_PTR VerifierAllocation : 1;
			ULONG_PTR AweAllocation : 1;
			ULONG_PTR Priority : MI_PFN_PRIORITY_BITS;
			ULONG_PTR MustBeCached : 1;
		};
	} u4;

} MMPFN, *PMMPFN;


typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(
	PVOID ThreadParameter
	);

typedef
VOID
(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);


//typedef struct _NON_PAGED_DEBUG_INFO {
//	USHORT      Signature;
//	USHORT      Flags;
//	ULONG       Size;
//	USHORT      Machine;
//	USHORT      Characteristics;
//	ULONG       TimeDateStamp;
//	ULONG       CheckSum;
//	ULONG       SizeOfImage;
//	ULONGLONG   ImageBase;
//} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;



#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY ARM64_RUNTIME_FUNCTION, *PARM64_RUNTIME_FUNCTION;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
	DWORD64 ImageBase;
	PARM64_RUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE {
	DWORD Count;
	BYTE  LocalHint;
	BYTE  GlobalHint;
	BYTE  Search;
	BYTE  Once;
	DWORD64 LowAddress;
	DWORD64 HighAddress;
	UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

NTSYSAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(
	DWORD64               ControlPc,
	PDWORD64              ImageBase,
	PUNWIND_HISTORY_TABLE HistoryTable
);


NTSYSAPI PIMAGE_NT_HEADERS RtlImageNtHeader(
	PVOID Base
);

#define MAX_STACK_DEPTH 32

#endif