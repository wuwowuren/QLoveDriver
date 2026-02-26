#include "PAGE_CR0_DISABLE.h"
#include <ntddk.h>
//#include <intrin.h>



#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#else
#define LOG_DEBUG(format,...) 

#endif // DEBUG
//关闭页面保护
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	__try {

		UINT64 cr0 = __readcr0();
		cr0 &= 0xfffffffffffeffff;
		_disable();
		__writecr0(cr0);
	}
	__except (1) {
		LOG_DEBUG("__except  %s  %08X\n", __FUNCTION__, GetExceptionCode());
		irql = KeRaiseIrqlToDpcLevel();
	}
	return irql;
}
//开启页面保护
void WPONx64(KIRQL irql)
{
	__try {
		UINT64 cr0 = __readcr0();
		cr0 |= 0x10000;
		__writecr0(cr0);
		_enable();
		KeLowerIrql(irql);
	}
	__except (1) {
		LOG_DEBUG("__except  %s  %08X\n", __FUNCTION__, GetExceptionCode());
	}
}