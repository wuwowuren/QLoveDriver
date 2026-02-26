#include "MachineCode.h"




#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ata.h>
#include <mountmgr.h>
#include <mountdev.h>

int disk_mode = 1;

#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif

PDRIVER_DISPATCH g_original_partmgr_control = 0;

PDRIVER_DISPATCH g_original_disk_control = 0;

PDRIVER_DISPATCH g_original_mountmgr_control = 0;

char* random_string(char* str, int size);



NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
    __in PEPROCESS Process
);

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID* Object
);


typedef struct _IOC_REQUEST {
    PVOID Buffer;
    ULONG BufferLength;
    PVOID OldContext;
    PIO_COMPLETION_ROUTINE OldRoutine;
} IOC_REQUEST, * PIOC_REQUEST;



typedef struct _IDSECTOR {
    USHORT  wGenConfig;
    USHORT  wNumCyls;
    USHORT  wReserved;
    USHORT  wNumHeads;
    USHORT  wBytesPerTrack;
    USHORT  wBytesPerSector;
    USHORT  wSectorsPerTrack;
    USHORT  wVendorUnique[3];
    CHAR    sSerialNumber[20];
    USHORT  wBufferType;
    USHORT  wBufferSize;
    USHORT  wECCSize;
    CHAR    sFirmwareRev[8];
    CHAR    sModelNumber[40];
    USHORT  wMoreVendorUnique;
    USHORT  wDoubleWordIO;
    USHORT  wCapabilities;
    USHORT  wReserved1;
    USHORT  wPIOTiming;
    USHORT  wDMATiming;
    USHORT  wBS;
    USHORT  wNumCurrentCyls;
    USHORT  wNumCurrentHeads;
    USHORT  wNumCurrentSectorsPerTrack;
    ULONG   ulCurrentSectorCapacity;
    USHORT  wMultSectorStuff;
    ULONG   ulTotalAddressableSectors;
    USHORT  wSingleWordDMA;
    USHORT  wMultiWordDMA;
    BYTE    bThisReserved[128];
} IDSECTOR, * PIDSECTOR;



// 替换派遣函数实现hook操作?
extern POBJECT_TYPE* IoDriverObjectType;
PDRIVER_DISPATCH add_irp_hook(const wchar_t* name, PDRIVER_DISPATCH new_func)

{

    // 初始化一个unicode string

    UNICODE_STRING str;

    RtlInitUnicodeString(&str, name);



    // 根据名称得到object指针

    PDRIVER_OBJECT driver_object = 0;

    NTSTATUS status = ObReferenceObjectByName(&str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (void**)&driver_object);

    if (!NT_SUCCESS(status)) return 0;



    // 这里就是修改派遣函数 实现hook操作

    PDRIVER_DISPATCH old_func = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];

    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = new_func;

   // n_log::printf("%ws hook %llx -> %llx \n", name, old_func, new_func);



    // 解除引用防止蓝屏

    ObDereferenceObject(driver_object);



    // 返回原始的派遣函数地址

    return old_func;

}






// IOCTL_STORAGE_QUERY_PROPERTY消息的完成例程处理
NTSTATUS my_storage_query_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    // 上下文,其实这个就是change_ioc函数里面申请的那个内存了
    if (context)
    {
        // 拿到我们前面保存好的数据
       IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        // 判断数据是否是获取硬盘序列号的
        if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            // 这里就是根据结构获取到序列号的偏移
            PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
            ULONG offset = desc->SerialNumberOffset;

            // 偏移有效的话,定位到地方后开始随机化序列号
            if (offset && offset < request.BufferLength)
            {
                char* serial = (char*)desc + offset;
                random_string(serial, 0);
            }
        }

        // 调用原始的完成例程
        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}

// SMART_RCV_DRIVE_DATA消息的完成例程处理
NTSTATUS my_smart_data_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    if (context)
    {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS))
        {
            char* serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
            random_string(serial, 0);
        }

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}


// 随机化字符串
char* random_string(char* str, int size)
{
    // 取到字符串长度
    if (size == 0) size = (int)strlen(str);
    if (size == 0) return 0;

    const int len = 63;
    const char char_maps[] = "QWERTYUIOPASDFGHJKLZXCVBNMzxcvbnmasdfghjklqwertyuiop0123456789";

    // 开始随机字符串
    unsigned long seed = KeQueryTimeIncrement();
    for (int i = 0; i < size; i++)
    {
        unsigned long index = RtlRandomEx(&seed) % len;
        str[i] = char_maps[index];
    }

    return str;
}

// 这个函数主要是辅助hook操作的
BOOLEAN change_ioc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine)
{
    // 先申请我们的一块内存空间用来保存我们后面需要的数据
    PIOC_REQUEST request = (PIOC_REQUEST)ExAllocatePool(NonPagedPool, sizeof(IOC_REQUEST));
    if (request == 0) return FALSE;

    // 保存缓冲区,后面这个缓冲区里面的数据就是要返回用户层的数据,我们要修改掉
    request->Buffer = irp->AssociatedIrp.SystemBuffer;

    // 保存缓冲区的大小
    request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;

    // 保存原始的irp上下文
    request->OldContext = ioc->Context;

    // 保存原始的完成例程函数
    request->OldRoutine = ioc->CompletionRoutine;

    // 修改控制位以达到我们想要的效果
    ioc->Control = SL_INVOKE_ON_SUCCESS;

    // 修改irp上下文为我们申请的内存
    ioc->Context = request;

    // 修改为我们自定义的完成例程函数
    ioc->CompletionRoutine = routine;

    return TRUE;
}




NTSTATUS my_ata_pass_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    if (context)
    {
       IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))
        {
            PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
            ULONG offset = (ULONG)pte->DataBufferOffset;
            if (offset && offset < request.BufferLength)
            {
                PIDENTIFY_DEVICE_DATA identity = (PIDENTIFY_DEVICE_DATA)((char*)request.Buffer + offset);
                if (identity)
                {
                    //if (disk_smart_disable)
                    //{
                    //    identity->CommandSetSupport.SmartCommands = 0;
                    //    identity->CommandSetActive.SmartCommands = 0;
                    //}

                    char* serial = (char*)identity->SerialNumber;
                    char* product = (char*)identity->FirmwareRevision;
                    char* product_revision = (char*)identity->ModelNumber;
                    if (serial && product && product_revision)
                    {
                        switch (disk_mode)
                        {
                        case 0:
                            //RtlCopyMemory(serial, disk_serial_buffer, strlen(serial));
                            //RtlCopyMemory(product, disk_product_buffer, strlen(product));
                            //RtlCopyMemory(product_revision, disk_product_revision_buffer, strlen(product_revision));
                            break;
                        case 1:
                            random_string(serial, 0);
                            random_string(product, 0);
                            random_string(product_revision, 0);
                            break;
                        case 2:
                            RtlZeroMemory(serial, strlen(serial));
                            RtlZeroMemory(product, strlen(product));
                            RtlZeroMemory(product_revision, strlen(product_revision));
                            break;
                        }
                    }
                }
            }
        }

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}


// 我们的处理函数
NTSTATUS my_disk_handle_control(PDEVICE_OBJECT device, PIRP irp)
{

    UCHAR* pName = PsGetProcessImageFileName(PsGetCurrentProcess());
    UCHAR GlobalName[0x40] = { 0 };
    RtlCopyMemory(GlobalName, pName, 16);
    if (_stricmp(GlobalName, "LOSTARK.exe") == 0) {
    
        LOG_DEBUG("LOSTARK  Disk \n");

        PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
        const unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;

        if (code == IOCTL_STORAGE_QUERY_PROPERTY)
        {
            if (StorageDeviceProperty == ((PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer)->PropertyId)
                change_ioc(ioc, irp, my_storage_query_ioc);
        }

        else if (code == IOCTL_ATA_PASS_THROUGH)
            change_ioc(ioc, irp, my_ata_pass_ioc);

        else if (code == SMART_RCV_DRIVE_DATA)
            change_ioc(ioc, irp, my_smart_data_ioc);
    
    }




    return g_original_disk_control(device, irp);
}







NTSTATUS my_part_info_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    if (context)
    {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength >= sizeof(PARTITION_INFORMATION_EX))
        {
            PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
            if (info->PartitionStyle == PARTITION_STYLE_GPT)
                random_string((char*)&info->Gpt.PartitionId, sizeof(GUID));
        }

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}

NTSTATUS my_part_layout_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    if (context)
    {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX))
        {
            PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
            if (PARTITION_STYLE_GPT == info->PartitionStyle)
                random_string((char*)&info->Gpt.DiskId, sizeof(GUID));
        }

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}

// guid
NTSTATUS my_partmgr_handle_control(PDEVICE_OBJECT device, PIRP irp)
{


    UCHAR* pName = PsGetProcessImageFileName(PsGetCurrentProcess());
    UCHAR GlobalName[0x40] = { 0 };
    RtlCopyMemory(GlobalName, pName, 16);
    if (_stricmp(GlobalName, "LOSTARK.exe") == 0) {
        
        LOG_DEBUG("LOSTARK partmgr  \n");

        PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
        unsigned long msg = ioc->Parameters.DeviceIoControl.IoControlCode;
        if (msg == IOCTL_DISK_GET_PARTITION_INFO_EX)
            change_ioc(ioc, irp, my_part_info_ioc);

        else if (msg == IOCTL_DISK_GET_DRIVE_LAYOUT_EX)
            change_ioc(ioc, irp, my_part_layout_ioc);
    }
    return g_original_partmgr_control(device, irp);
}


// 开始执行hook操作?

NTSTATUS my_mount_points_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    if (context)
    {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS))
        {
            PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
            for (DWORD i = 0; i < points->NumberOfMountPoints; ++i)
            {
                PMOUNTMGR_MOUNT_POINT point = &points->MountPoints[i];

                if (point->UniqueIdOffset)
                    point->UniqueIdLength = 0;

                if (point->SymbolicLinkNameOffset)
                    point->SymbolicLinkNameLength = 0;
            }
        }

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }
    return STATUS_SUCCESS;
}

NTSTATUS my_mount_unique_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{



    if (context)
    {
        IOC_REQUEST request = *(PIOC_REQUEST)context;
        ExFreePool(context);

        if (request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID))
            ((PMOUNTDEV_UNIQUE_ID)request.Buffer)->UniqueIdLength = 0;

        if (request.OldRoutine && irp->StackCount > 1)
            return request.OldRoutine(device, irp, request.OldContext);
    }

    return STATUS_SUCCESS;
}

// column
NTSTATUS my_mountmgr_handle_control(PDEVICE_OBJECT device, PIRP irp)
{

    UCHAR* pName = PsGetProcessImageFileName(PsGetCurrentProcess());
    UCHAR GlobalName[0x40] = { 0 };
    RtlCopyMemory(GlobalName, pName, 16);
    if (_stricmp(GlobalName, "LOSTARK.exe") == 0) {

        LOG_DEBUG("LOSTARK mountmgr  \n");

        PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
        const unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;

        if (code == IOCTL_MOUNTMGR_QUERY_POINTS)
            change_ioc(ioc, irp, my_mount_points_ioc);
        else if (code == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID)
            change_ioc(ioc, irp, my_mount_unique_ioc);


    }
    return g_original_mountmgr_control(device, irp);
}






BOOLEAN start_hook()
{

    // 替换派遣函数,相当于对函数进行了hook

    // 当然也可以进行真正的hook操作,pg应该不会检查这些地方
    // hook这里主要是为了修改硬盘的一些guid
    g_original_partmgr_control = add_irp_hook(L"\\Driver\\partmgr", my_partmgr_handle_control);
    // hook这里主要是为了修改硬盘的一些序列号

    g_original_disk_control = add_irp_hook(L"\\Driver\\disk", my_disk_handle_control);

    // hook这里主要是为了修改磁盘的一些volume
    g_original_mountmgr_control = add_irp_hook(L"\\Driver\\mountmgr", my_mountmgr_handle_control);

    return g_original_partmgr_control && g_original_disk_control && g_original_mountmgr_control;




}