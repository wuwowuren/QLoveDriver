#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	
#include<ntimage.h>




// PE文件签名定义
#define IMAGE_DOS_SIGNATURE 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE 0x00004550   // PE\0\0
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B  // PE32+

// 数据目录索引
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

// 展开操作码定义
#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128 6
#define UWOP_SAVE_XMM128_FAR 7
#define UWOP_PUSH_MACHFRAME 8

// 标志位定义
#define UNW_FLAG_EHANDLER 0x01   // 函数有异常处理程序
#define UNW_FLAG_UHANDLER 0x02   // 函数有终止处理程序
#define UNW_FLAG_CHAININFO 0x04  //展开信息链接到另一个函数



typedef struct _MOD_INFO {
	 ULONG64 ModBase;
	 PIMAGE_DOS_HEADER DosHeader;
	 PIMAGE_NT_HEADERS pNtHeader;
	 USHORT SectionSize;
	 PIMAGE_SECTION_HEADER SectionsArray;
	 ULONG64 ModSize;
} MOD_INFO, * PMOD_INFO;


typedef struct _RUNTIME_FUNCTION {
	ULONG BeginAddress;
	ULONG EndAddress;
	ULONG UnwindData;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;



typedef struct _C_SCOPE_TABLE {
	ULONG Begin;
	ULONG End;
	ULONG Handler;
	ULONG Target;
}C_SCOPE_TABLE;

//00000000 C_SCOPE_TABLE   struc; (sizeof = 0x10, mappedto_2366)
//00000000; XREF:.rdata : 00000001400421DC / r
//00000000;.rdata:00000001400423C4 / r ...
//00000000 Begin           dd ? ; offset rva
//00000004 End             dd ? ; offset rva pastend
//00000008 Handler         dd ? ; offset rva
//0000000C Target          dd ? ; offset rva
//00000010 C_SCOPE_TABLE   ends

typedef struct _RUNTIME_HANDLER {
	ULONG __C_specific_handler;
	ULONG Number;
	C_SCOPE_TABLE HandlerTable[0x10];
} RUNTIME_HANDLER, * PRUNTIME_HANDLER;





typedef struct _UNWIND_INFO_HDR {
	UCHAR Ver : 3;
	UCHAR Flags : 5;
	UCHAR PrologSize;
	UCHAR CntUnwindCodes;
	UCHAR FrReg_FrRegOff;
}UNWIND_INFO_HDR ,*PUNWIND_INFO_HDR;



// 展开代码结构
typedef union _UNWIND_CODE {
	struct {
		UCHAR CodeOffset;
		UCHAR UnwindOp : 4;
		UCHAR OpInfo : 4;
	} DUMMYSTRUCTNAME;
	UINT16 FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

// 展开信息结构
typedef struct _UNWIND_INFO {
	UINT8 Version : 3;
	UINT8 Flags : 5;
	UINT8 SizeOfProlog;
	UINT8 CountOfCodes;
	UINT8 FrameRegister : 4;
	UINT8 FrameOffset : 4;
	// UNWIND_CODE UnwindCode[1];
	// 可选字段:
	// union {
	//     uint32_t ExceptionHandler;
	//     uint32_t FunctionEntry;
	// };
	// uint32_t ExceptionData[];
} UNWIND_INFO, * PUNWIND_INFO;


typedef struct  _MOD_SECTION {
	HANDLE FileHandle;
	HANDLE SectionHandle;
	HANDLE Process;
	PVOID ViewBase;
	ULONGLONG ViewSize;
}MOD_SECTION, * PMOD_SECTION;


typedef struct _F_BLOCK_COPY {
	RUNTIME_FUNCTION RunTime;
	PVOID Ptr;
}F_BLOCK_COPY, * PF_BLOCK_COPY;


//   STATUS_INVALID_HANDLE   ModBaseAddress 访问异常
//   STATUS_ACCESS_VIOLATION  Code  SectionName  pAdr 内存访问异常
//   STATUS_BAD_INITIAL_STACK  未能搜索到

NTSTATUS InitializationModInfo(ULONG64 ModBaseAddress, PMOD_INFO ModInfo);
//   返回值 0 成功  错误如下
NTSTATUS ZqSearchMoudleCode(PMOD_INFO Mod,  //模块基地址
	                        char* Code,  // 搜索的字节代码 掩码nop 0x90
	                        DWORD CodeSize,  // 字节代码长度
	                        char* SectionName, //搜索的节点名
	                        DWORD dFlags,  //搜索标志  貌似未使用
	                        PVOID* pAdr); // 搜索到的指针

// STATUS_IN_PAGE_ERROR 节点找到了 但是内存不可访问
NTSTATUS  ZqGetSectionPtr(PMOD_INFO Mod, //模块基地址
	char* SectionName, //节点名
	PVOID* Ptr,  // 返回的节点指针
	DWORD* pSize); // 返回的节点数据指针长度


//一定要注意，不是所有函数都是正确加载的，有可能被移动到了其他地方

NTSTATUS ZqGetModRunTime(PMOD_INFO Mod, 
	                     PRUNTIME_FUNCTION* pRunTime, // 返回的指针
	                     DWORD* pCount); // 返回数量

//NTSTATUS ZqGetModRunTimeR(PMOD_INFO Mod, PRUNTIME_FUNCTION* pRunTime, DWORD* pCount);


// 搜索函数的起始地址   
NTSTATUS ZqSearchFunction(PMOD_INFO Mod, 
	                      char* pCode,  // 搜索的字节代码 掩码nop 0x90
	                      DWORD CodeSize, 
	                      _Outptr_ PVOID* fPtr,
	                      PRUNTIME_FUNCTION pRunTime);



  //如果有异常返回异常处理返回异常起始点
NTSTATUS ZqGetRunTimeUnwindHandler(PMOD_INFO Mod, PRUNTIME_FUNCTION pRuntime, 
	_Outptr_ PRUNTIME_HANDLER* pRunHandler);


NTSTATUS ZqGetFunctionHander(PMOD_INFO Mod, 
	                         char* pCode, 
	                         DWORD nSize, 
	                         _Outptr_ PRUNTIME_HANDLER* pRunHandler, 
	                         _Outptr_ LPVOID* fPtr);

NTSTATUS ZqGetFunctionSize(PMOD_INFO Mod, PVOID fPtr, _Out_ DWORD* pSize);



// 取函数的代码块   
NTSTATUS ZqGetFunctionBlock(PMOD_INFO Mod,  //
	PVOID fPtr,    //模块指针
	PRUNTIME_FUNCTION pRuntime, // RunTime
	DWORD InCount,  // 个数
	DWORD* pCount); // 如果失败了返回需要的数量节点





// 取函数的代码块  由于有的函数 初始化之后就被释放了  我们用LoadSection加载之后  用此函数 拷贝出来  
NTSTATUS ZqGetFunctionBlockCopy(PMOD_INFO Mod,  //
	PVOID fPtr,    //模块指针
	PF_BLOCK_COPY pRuntime, // RunTime
	DWORD InCount,  // 个数
	DWORD* pCount); // 如果失败了返回需要的数量节点


// 释放
VOID ZqFreeBlockCopy(PF_BLOCK_COPY pRuntime, DWORD InCount);


// 映射模块
NTSTATUS ZqLoadModSection(UNICODE_STRING* pModName, PMOD_SECTION pModSection);

// 解除映射
NTSTATUS ZqUnLoadModSection(PMOD_SECTION pModSection);

// 根据指针返回导出函数的名字
NTSTATUS ZqPtrGetFunctionName(PMOD_INFO Mod, PVOID Ptr, CHAR** cSearchFnName);

// 
PVOID ZqAllocateMemoryWithTag(SSIZE_T Size, char* SectionName);
