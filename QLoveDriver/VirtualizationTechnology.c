#include "VirtualizationTechnology.h"
#include "msr.h"
#include "asm.h"

#ifdef DEBUG
#define Log(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#else
#define Log(format,...) 

#endif // DEBUG



typedef struct 
{
		   unsigned PE : 1;
		   unsigned MP : 1;
		   unsigned EM : 1;
		   unsigned TS : 1;
		   unsigned ET : 1;
		   unsigned NE : 1;
		   unsigned Reserved_1 : 10;
		   unsigned WP : 1;
		   unsigned Reserved_2 : 1;
		   unsigned AM : 1;
		   unsigned Reserved_3 : 10;
		   unsigned NW : 1;
		   unsigned CD : 1;
		   unsigned PG : 1;
		   unsigned Reserved_64:32;
}_CR0;

typedef struct {
		unsigned VME : 1;
		unsigned PVI : 1;
		unsigned TSD : 1;
		unsigned DE : 1;
		unsigned PSE : 1;
		unsigned PAE : 1;
		unsigned MCE : 1;
		unsigned PGE : 1;
		unsigned PCE : 1;
		unsigned OSFXSR : 1;
		unsigned PSXMMEXCPT : 1;
		unsigned UNKONOWN_1 : 1;             //These are zero
		unsigned UNKONOWN_2 : 1;             //These are zero
		unsigned VMXE : 1;                     //It's zero in normal
		unsigned Reserved : 18;             //These are zero
		unsigned Reserved_64:32;
}_CR4;


typedef struct _IA32_FEATURE_CONTROL_MSR
{
unsigned Lock : 1;              // Bit 0 is the lock bit - cannotbe modified once lock is set
unsigned Reserved1 : 1;              //Undefined
unsigned EnableVmxon : 1;              // Bit 2. Ifthis bit is clear, VMXON causes a general protection exception
unsigned Reserved2 : 29;  //Undefined
unsigned Reserved3 : 32;  //Undefined

} IA32_FEATURE_CONTROL_MSR;

#pragma pack (2)
typedef struct  {
	unsigned short Limit;
	ULONG_PTR base;
}IDTR;
static_assert(sizeof(IDTR) == 10, "Size check");
#pragma pack ()
///////////////------------------------------------

#pragma warning(disable:4214)
typedef union {
	ULONG64 all;
	struct
	{
		ULONG64 limit_low : 16;
		ULONG64 base_low : 16;
		ULONG64 base_mid : 8;
		ULONG64 type : 4;
		ULONG64 system : 1;
		ULONG64 dpl : 2;
		ULONG64 present : 1;
		ULONG64 limit_high : 4;
		ULONG64 avl : 1;
		ULONG64 l : 1;  //!< 64-bit code segment (IA-32e mode only)
		ULONG64 db : 1;
		ULONG64 gran : 1;
		ULONG64 base_high : 8;
	} fields;
}SegmentDescriptor;
static_assert(sizeof(SegmentDescriptor) == 8, "Size check");

typedef union {
	unsigned short all;
	struct {
		unsigned short rpl : 2;  //!< Requested Privilege Level
		unsigned short ti : 1;   //!< Table Indicator
		unsigned short index : 13;
	} fields;
}SegmentSelector;

typedef struct {
	SegmentDescriptor descriptor;
	ULONG32 base_upper32;
	ULONG32 reserved;
}SegmentDesctiptorX64;

// Returns the segment descriptor corresponds to the SegmentSelector
_Use_decl_annotations_ static SegmentDescriptor *VmpGetSegmentDescriptor(
	ULONG_PTR descriptor_table_base, USHORT segment_selector) {
	PAGED_CODE()
		const SegmentSelector * ss = (SegmentSelector *)&segment_selector;
	return (SegmentDescriptor *)(descriptor_table_base + ss->fields.index * sizeof(SegmentDescriptor));
}

// Returns a base address of segment_descriptor
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBaseByDescriptor(
	const SegmentDescriptor *segment_descriptor) {
	PAGED_CODE()

		// Calculate a 32bit base address
		const auto base_high = (int)segment_descriptor->fields.base_high << (6 * 4);
	const auto base_middle = (int)segment_descriptor->fields.base_mid << (4 * 4);
	const auto base_low = (int)segment_descriptor->fields.base_low;
	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed

	//__debugbreak();

	if (!segment_descriptor->fields.system) {
		SegmentDesctiptorX64 * desc64 = (SegmentDesctiptorX64 *)segment_descriptor;
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}

// Returns a base address of the segment specified by SegmentSelector
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBase(
	ULONG_PTR gdt_base, USHORT segment_selector) {
	PAGED_CODE()

	const SegmentSelector * ss = (SegmentSelector *)&segment_selector;
	if (!ss->all) {
		return 0;
	}

	if (ss->fields.ti) {
		//__debugbreak();
		SegmentDescriptor * local_segment_descriptor = VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
		ULONG_PTR ldt_base = VmpGetSegmentBaseByDescriptor(local_segment_descriptor);
		SegmentDescriptor * segment_descriptor = VmpGetSegmentDescriptor(ldt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		//__debugbreak();
		SegmentDescriptor *  segment_descriptor = VmpGetSegmentDescriptor(gdt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
}

//typedef struct _VMX_CPU
//{
//	PVOID pVMXONRegion; //VMXON的虚拟地址
//	PHYSICAL_ADDRESS pVMXONRegion_PA; //VMXON的物理地址
//	PVOID pVMCSRegion; //VMCS的虚拟地址
//	PHYSICAL_ADDRESS pVMCSRegion_PA; //VMCS的物理地址
//	PVOID pHostEsp; //主机的Esp
//
//	BOOLEAN bVTStartSuccess; //用于记录是否开启成功
//}VMX_CPU, *PVMX_CPU;

BOOLEAN IsVTEnable()
{
	int cpu_info[4] = { 0 };
	_CR0 cr0;
	_CR4 cr4;
	__cpuid(cpu_info, 1);
	if ((cpu_info[0] & (1 << 5)) == 0)
	{
		Log("该CPU 不支持 VirtualizationTechnology \n");
		return FALSE;
	}
    *((INT64 *)&cr0) = __readcr0();
	if (cr0.PE != 1 || cr0.PG != 1 || cr0.NE != 1)
	{
		Log("请在Bios里面设置VT选项!\n");
		return FALSE;
	}
	*((INT64 *)&cr4) = __readcr4();
	if (cr4.VMXE == 1)
	{
		Log("已经有VT啦!\n");
		return FALSE;
	}
	IA32_FEATURE_CONTROL_MSR msr;
	*((INT64 *)&msr) = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (msr.Lock != 1)
	{
		Log("VT 指令没有锁定!\n");
		return FALSE;
	}
	Log("当前CPU支持VT!\n");
	return TRUE;
}


typedef struct {
	PVOID pVMXONVirtualAddress;
	PHYSICAL_ADDRESS VMXON_VmsSupportPhysicalAddress;
	PVOID pVMSCVirtualAddress;
	PHYSICAL_ADDRESS VMSC_VmsSupportPhysicalAddress;
	PVOID pIOmapVirtualAddressA;
	PHYSICAL_ADDRESS IOMAP_PhysicalAddressA;
	PVOID pIOmapVirtualAddressB;
	PHYSICAL_ADDRESS IOMAP_PhysicalAddressB;
	PVOID pMsrVirtualAddress;
	PHYSICAL_ADDRESS Msr_PhysicalAddress;
	PVOID pStackVirtualAddress;
}VMXCPU,*PVMXCPU;

static VMXCPU  m_VMXCPU = { 0 };

static BOOLEAN bSucessVMX = FALSE;

void vmxCR4(BYTE iType) {
	_CR4 cr4;
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	*((INT64 *)&cr4) = __readcr4();
	KeLowerIrql(irql);
	Log("设置CR4前: %I64X\n", __readcr4());
	cr4.VMXE = iType;
	irql = KeRaiseIrqlToDpcLevel();
	__writecr4(*((INT64 *)&cr4));
	KeLowerIrql(irql);
	Log("设置CR4后: %I64X\n", __readcr4());
}


#define ENDFREE(x) if(x != NULL) {ExFreePool(x);x = NULL;}

void freeVMXCPU(PVMXCPU vmxcpu) 
{
	Log("freeVMXCPU \n");
	ENDFREE(vmxcpu->pVMSCVirtualAddress);
	ENDFREE(vmxcpu->pVMXONVirtualAddress);
	ENDFREE(vmxcpu->pStackVirtualAddress);
	ENDFREE(vmxcpu->pIOmapVirtualAddressA);
	ENDFREE(vmxcpu->pIOmapVirtualAddressB);
	ENDFREE(vmxcpu->pMsrVirtualAddress);

}


static ULONG  VmxAdjustControls(ULONG Ctl, ULONG Msr)
{
	LARGE_INTEGER MsrValue;
	MsrValue.QuadPart = __readmsr(Msr);
	Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}


void VMMEntryPoint() {


	__debugbreak();

}

void SetupVMCS() {




	__try {

		// 执行控制域
		Log("执行控制域\n");


		ULONG m_PIN_BASED_VM_EXEC_CONTROL = VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS);
		__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, m_PIN_BASED_VM_EXEC_CONTROL);
		Log("PIN_BASED_VM_EXEC_CONTROL %08X\n", m_PIN_BASED_VM_EXEC_CONTROL);

		ULONG m_CPU_BASED_VM_EXEC_CONTROL = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS);
		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, m_CPU_BASED_VM_EXEC_CONTROL);
		Log("CPU_BASED_VM_EXEC_CONTROL %08X\n", m_CPU_BASED_VM_EXEC_CONTROL);

		// 进入控制域
		Log("进入控制域\n");

		ULONG m_VM_ENTRY_CONTROLS = VmxAdjustControls(0, MSR_IA32_VMX_ENTRY_CTLS);
		__vmx_vmwrite(VM_ENTRY_CONTROLS, m_VM_ENTRY_CONTROLS);
		Log("VM_ENTRY_CONTROLS %08X\n", m_VM_ENTRY_CONTROLS);
		// 退出控制域
		Log("退出控制域\n");
		ULONG m_VM_EXIT_CONTROLS = VmxAdjustControls(0, MSR_IA32_VMX_EXIT_CTLS);
		__vmx_vmwrite(VM_EXIT_CONTROLS, m_VM_EXIT_CONTROLS);
		Log("VM_EXIT_CONTROLS %08X\n", m_VM_EXIT_CONTROLS);

		//
		ULONG m_VM_EXIT_PROCBASED_CONTROLS = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS2);
		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, m_VM_EXIT_PROCBASED_CONTROLS);
		Log("VM_PROCBASED_CONTROLS %08X\n", m_VM_EXIT_PROCBASED_CONTROLS);

		//--------------
		__vmx_vmwrite(IO_BITMAP_A, m_VMXCPU.IOMAP_PhysicalAddressA.QuadPart);
		__vmx_vmwrite(IO_BITMAP_B, m_VMXCPU.IOMAP_PhysicalAddressB.QuadPart);
		__vmx_vmwrite(MSR_BITMAP, m_VMXCPU.Msr_PhysicalAddress.QuadPart);



	}
	__except (1) {

		Log("异常好多\n");

	}
	//-------设置HOST

	__try {


		Log("设置HOST\n");
		__vmx_vmwrite(HOST_CR0, __readcr0());
		__vmx_vmwrite(HOST_CR3, __readcr3());
		__vmx_vmwrite(HOST_CR4, __readcr4());

		Log("设置HOST  IN\n");

		__vmx_vmwrite(HOST_ES_SELECTOR, AsmReadES() & 0xF8);
		__vmx_vmwrite(HOST_CS_SELECTOR, AsmReadCS() & 0xF8);
		__vmx_vmwrite(HOST_DS_SELECTOR, AsmReadDS() & 0xF8);
		__vmx_vmwrite(HOST_FS_SELECTOR, AsmReadFS() & 0xF8);
		__vmx_vmwrite(HOST_GS_SELECTOR, AsmReadGS() & 0xF8);
		__vmx_vmwrite(HOST_SS_SELECTOR, AsmReadSS() & 0xF8);
		__vmx_vmwrite(HOST_TR_SELECTOR, AsmReadTR() & 0xF8);

		Log("设置ES %08X\n", AsmReadES() & 0xF8);
		Log("设置CS %08X\n", AsmReadCS() & 0xF8);
		Log("设置DS %08X\n", AsmReadDS() & 0xF8);
		Log("设置FS %08X\n", AsmReadFS() & 0xF8);
		Log("设置GS %08X\n", AsmReadGS() & 0xF8);
		Log("设置SS %08X\n", AsmReadSS() & 0xF8);
		Log("设置TR %08X\n", AsmReadTR() & 0xF8);


	}
	__except (1) {

		Log("设置HOST 异常\n");

	}



	__try {

		//__vmx_vmwrite(HOST_TR_BASE, 0x80042000);

		// 全局描述表
	IDTR GdtBase = { 0 };
	_sgdt(&GdtBase);


	Log("GDTRBASE %I64X\n  GDTRLimit : %04X\n", GdtBase.base, GdtBase.Limit);
	//__readmsr)

	__vmx_vmwrite(HOST_GDTR_BASE, GdtBase.base);

	// 中断表
	IDTR IdtBase = {0};
	__sidt(&IdtBase);

	Log("IDTRBASE %I64X\n IDTRLimit:%04X\n", IdtBase.base, IdtBase.Limit);
	__vmx_vmwrite(HOST_IDTR_BASE, IdtBase.base);

	//LONGLONG TRBASE = AsmReadTR();

	ULONG_PTR btr = VmpGetSegmentBase(GdtBase.base, AsmReadTR());

	__vmx_vmwrite(HOST_TR_BASE, btr);

	Log("设置TR %I64X\n", btr);


	}
	__except (1) {

		Log("设置中断表异常\n");
	}
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP)); // KiFastCallEntry

	__vmx_vmwrite(HOST_RSP, (ULONGLONG)(((char *)m_VMXCPU.pStackVirtualAddress) + (PAGE_SIZE * 16)));     //Host 临时栈
	__vmx_vmwrite(HOST_RIP, (ULONGLONG)VMMEntryPoint);                  //这里定义我们的VMM处理程序入口

	Log("HOST_RSP : %I64X\n", (ULONGLONG)(((char *)m_VMXCPU.pStackVirtualAddress) + (PAGE_SIZE * 16)));
	Log("HOST_RIP : %I64X\n", (ULONGLONG)VMMEntryPoint);

	
	ULONG m_VM_ENTRY_CONTROLS = VmxAdjustControls(0, MSR_IA32_VMX_ENTRY_CTLS);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, m_VM_ENTRY_CONTROLS);
	Log("VM_ENTRY_CONTROLS : %I64X\n", m_VM_ENTRY_CONTROLS);

	ULONG m_VM_EXIT_CONTROLS = VmxAdjustControls(0, MSR_IA32_VMX_EXIT_CTLS);
	__vmx_vmwrite(VM_EXIT_CONTROLS, m_VM_EXIT_CONTROLS);
	Log("VM_ENTRY_CONTROLS : %I64X\n", m_VM_EXIT_CONTROLS);





}

NTSTATUS StartVirtualTechnology() 
{
	if (!IsVTEnable())
		return STATUS_UNSUCCESSFUL;
	vmxCR4(1);
	// 一定要足够大 不然要蓝屏
	m_VMXCPU.pVMXONVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 16, 'vmx');
	if (m_VMXCPU.pVMXONVirtualAddress == NULL) {
		Log("ExAllocatePoolWithTag 失败\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(m_VMXCPU.pVMXONVirtualAddress, PAGE_SIZE * 16);
	LONG nVer = (LONG)__readmsr(MSR_IA32_VMX_BASIC);
	*(PLONG)m_VMXCPU.pVMXONVirtualAddress = nVer;
	m_VMXCPU.VMXON_VmsSupportPhysicalAddress = MmGetPhysicalAddress(m_VMXCPU.pVMXONVirtualAddress);
	
	
	if (__vmx_on((INT64 *)&m_VMXCPU.VMXON_VmsSupportPhysicalAddress) != 0)
	{
		freeVMXCPU(&m_VMXCPU);
		vmxCR4(0);
		Log("__vmx_on 失败\n");
		return STATUS_UNSUCCESSFUL;
	}
	Log("__vmx_on 成功\n");

	bSucessVMX = TRUE;

	// 一定要足够大 不然要蓝屏
	m_VMXCPU.pStackVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 16, 'stk');
	if (m_VMXCPU.pStackVirtualAddress == NULL) {
		Log("ExAllocatePoolWithTag 失败\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(m_VMXCPU.pStackVirtualAddress, PAGE_SIZE * 16);




	//------------- IO MAP MSR 申请

	m_VMXCPU.pIOmapVirtualAddressA = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 16, 'ioa');
	m_VMXCPU.pIOmapVirtualAddressB = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 16, 'iob');
	m_VMXCPU.pMsrVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 16, 'msr');

	RtlZeroMemory(m_VMXCPU.pIOmapVirtualAddressA, PAGE_SIZE * 16);
	RtlZeroMemory(m_VMXCPU.pIOmapVirtualAddressB, PAGE_SIZE * 16);
	RtlZeroMemory(m_VMXCPU.pMsrVirtualAddress, PAGE_SIZE * 16);

	m_VMXCPU.IOMAP_PhysicalAddressA = MmGetPhysicalAddress(m_VMXCPU.pIOmapVirtualAddressA);
	m_VMXCPU.IOMAP_PhysicalAddressB = MmGetPhysicalAddress(m_VMXCPU.pIOmapVirtualAddressB);
	m_VMXCPU.Msr_PhysicalAddress = MmGetPhysicalAddress(m_VMXCPU.pMsrVirtualAddress);

	// 一定要足够大 不然要蓝屏
	m_VMXCPU.pVMSCVirtualAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 16, 'mcs');
	if (m_VMXCPU.pVMSCVirtualAddress == NULL) {
		Log("ExAllocatePoolWithTag 失败\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(m_VMXCPU.pVMSCVirtualAddress, PAGE_SIZE * 16);

	*(PLONG)m_VMXCPU.pVMSCVirtualAddress = nVer;
	m_VMXCPU.VMSC_VmsSupportPhysicalAddress = MmGetPhysicalAddress(m_VMXCPU.pVMSCVirtualAddress);
	__vmx_vmclear((INT64 *)&m_VMXCPU.VMSC_VmsSupportPhysicalAddress);
	__vmx_vmptrld((INT64 *)&m_VMXCPU.VMSC_VmsSupportPhysicalAddress);

	SetupVMCS();
	char r = __vmx_vmlaunch();
	if (r != 0)
	{
		size_t launch_error = 0;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &launch_error);
		StopVirtualTechnology();
		Log("__vmx_vmlaunch %d\n", launch_error);
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS StopVirtualTechnology() 
{
	if (!bSucessVMX) {
		Log("没有安装成功 不用卸载\n");
		return STATUS_UNSUCCESSFUL;
	}
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	__try {
		__vmx_off();
	}
	__except (1) {
		Log("__vmx_off 异常\n");
	}
	KeLowerIrql(irql);
	vmxCR4(0);
	freeVMXCPU(&m_VMXCPU);
	bSucessVMX = FALSE;
	return STATUS_SUCCESS;


}









