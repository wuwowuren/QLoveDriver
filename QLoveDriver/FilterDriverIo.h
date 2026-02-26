#pragma once

#include <wdm.h>
#include "DEBUG_LOG.h"






typedef NTSTATUS(*HANDLE_DRIVER_IRP)(PDEVICE_OBJECT pDevObj, PIRP pIrp);

typedef struct _HOOK_DRIVER_DISPATH{

	PDRIVER_DISPATCH NewMajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

	PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

	PDRIVER_OBJECT pDevObj;

}HOOK_DRIVER_DISPATH;


VOID START_HOOK_DRIVER(PDRIVER_OBJECT pDevObj, HOOK_DRIVER_DISPATH* pHOOK);









//BOOLEAN  HOOK_DRIVER_DISPATH_CTL();
//
//NTSTATUS NewDispatchCtl(PDEVICE_OBJECT pDevObj, PIRP pIrp);
//
//void SetOldDispatch(FDispatch DisPath);
