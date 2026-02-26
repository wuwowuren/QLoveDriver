

#include <defs.h>
#include <devicedefs.h>

#include "Shark.h"

#include "Jump.h"
#include "Reload.h"
#include "PatchGuard.h"

VOID
NTAPI
DriverUnload(
    __in PDRIVER_OBJECT DriverObject
);

NTSTATUS
NTAPI
DeviceCreate(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
);

NTSTATUS
NTAPI
DeviceClose(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
);

NTSTATUS
NTAPI
DeviceWrite(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
);

NTSTATUS
NTAPI
DeviceRead(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
);

NTSTATUS
NTAPI
DeviceControl(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
);

NTSTATUS
NTAPI
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DeviceName = { 0 };


    RtlInitUnicodeString(&DeviceName, LOADER_DEVICE_STRING);

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,

        FALSE,
        &DeviceObject);

    if ((RTL_SOFT_ASSERT(NT_SUCCESS(Status)))) {
        DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)DeviceCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)DeviceClose;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)DeviceWrite;
        DriverObject->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)DeviceRead;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DeviceControl;

        RtlInitUnicodeString(&SymbolicLinkName, LOADER_SYMBOLIC_STRING);

        Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);

        if ((RTL_SOFT_ASSERT(NT_SUCCESS(Status)))) {
            DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;

            InitializeLoadedModuleList(NULL);

#ifndef VMP
            DbgPrint("Shark - load\n");
#endif // !VMP
        }
        else {
 
        }
    }

    return Status;
}

VOID
NTAPI
DriverUnload(
    __in PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING SymbolicLinkName = { 0 };

    RtlInitUnicodeString(&SymbolicLinkName, LOADER_SYMBOLIC_STRING);
    IoDeleteSymbolicLink(&SymbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

#ifndef VMP
    DbgPrint("Shark - unload\n");
#endif // !VMP
}

NTSTATUS
NTAPI
DeviceCreate(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(
        Irp,
        IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
NTAPI
DeviceClose(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(
        Irp,
        IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
NTAPI
DeviceWrite(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(
        Irp,
        IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
NTAPI
DeviceRead(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(
        Irp,
        IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
NTAPI
DeviceControl(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpSp = NULL;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
    case 0: {
        PPATCHGUARD_BLOCK PatchGuardBlock = NULL;

        PatchGuardBlock = ExAllocatePool(
            NonPagedPool,
            sizeof(PATCHGUARD_BLOCK));

        if (NULL != PatchGuardBlock) {
            RtlZeroMemory(PatchGuardBlock, sizeof(PATCHGUARD_BLOCK));

#ifdef _WIN64
            DisablePatchGuard(PatchGuardBlock);
#endif // _WIN64

            // free must after PatchGuard context cleared
            // ExFreePool(PatchGuardBlock);
        }

        Irp->IoStatus.Information = 0;

        break;
    }

    default: {
        Irp->IoStatus.Information = 0;
        Status = STATUS_INVALID_DEVICE_REQUEST;

        break;
    }
    }

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(
        Irp,
        IO_NO_INCREMENT);

    return Status;
}
