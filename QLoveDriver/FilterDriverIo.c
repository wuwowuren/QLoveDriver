#include "FilterDriverIo.h"




BOOLEAN HOOK_DRIVER_DISPATH_CTL()
{
	return 0;
}


//NTSTATUS NewDispatchCtl(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
//
//	//PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
//
//	//LOG_DEBUG("IO ControlCode  %08X  \n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
//	if (RunDispatch != 0){
//		return RunDispatch(pDevObj, pIrp);
//	}
//	return STATUS_SUCCESS;
//}








VOID START_HOOK_DRIVER(PDRIVER_OBJECT pDevObj, HOOK_DRIVER_DISPATH* pHOOK)
{
	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++){
		pHOOK->MajorFunction[i] = pDevObj->MajorFunction[i];
	}
	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		pDevObj->MajorFunction[i] = pHOOK->NewMajorFunction[i];
	}
	pHOOK->pDevObj = pDevObj;
	return ;
}
