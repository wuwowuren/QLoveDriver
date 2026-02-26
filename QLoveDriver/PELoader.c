#include "PELoader.h"

#include "BASE_TABLE.h"


#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format "\n",__LINE__, __VA_ARGS__);
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif // DEBUG

char* CharToUper(char* cStr, BOOLEAN isAllocateMemory)
{

    //RtlUpcaseUnicodeString()

    char* ret = NULL;
    if (isAllocateMemory)
    {
        // 需要申请内存
        int len = strlen(cStr) + 2;
        ret = ExAllocatePool(PagedPool, len);
        memset(ret, 0, len);
        memcpy(ret, cStr, len - 2);
    }
    else
    {
        ret = cStr;
    }
    _strupr(ret);

    return ret;
}


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// private
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;


extern NTSTATUS NTAPI _ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

ULONG_PTR QuerySysModule(IN char* ModuleName, OUT ULONG_PTR* module)
{
    if (strlen(ModuleName) <= 0)
    {
       // LOG("Moudle name is null\r\n");
        return 0;
    }
    ULONG moduleSize = 0;
    char* tempWStr = CharToUper(ModuleName, TRUE);
    KdPrintEx((77, 0, "%s\r\n", tempWStr));
    RTL_PROCESS_MODULES processInfo;
    ULONG64 retPtr = 0;
    NTSTATUS status = _ZwQuerySystemInformation(SystemModuleInformation, &processInfo, sizeof(processInfo), (PULONG)&retPtr);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        ULONG len = (ULONG)retPtr + sizeof(RTL_PROCESS_MODULES);
        // 首先使其出错，得到返回的长度
        // 申请长度
        PRTL_PROCESS_MODULES mem = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, len);

        memset(mem, 0x0, len);
        // 再次查询，得到正确的结果
        status = _ZwQuerySystemInformation(SystemModuleInformation, mem, len, (PULONG)&retPtr);

        if (!NT_SUCCESS(status))
        {
            // 判断 
            ExFreePool(mem);
            return 0;
        }

        // 开始查询
        for (ULONG i = 0; i < mem->NumberOfModules; i++)
        {
            PRTL_PROCESS_MODULE_INFORMATION pModule = &mem->Modules[i];
            CharToUper(pModule->FullPathName, FALSE);
            if (strstr(pModule->FullPathName, tempWStr))
            {
              //  LOG(">>>> %s %llX %08X\r\n", pModule->FullPathName, pModule->ImageBase, pModule->ImageSize);
                if (module)
                {
                    *module = (ULONG_PTR)pModule->ImageBase;

                }
                moduleSize = pModule->ImageSize;
                break;
            }
        }
        ExFreePool(tempWStr);
        ExFreePool(mem);

    }

    return moduleSize;
}

// 复制PE 结构头部
void CopyIamgeHeader(PUCHAR buffer, PUCHAR ImageBaseBuffer)
{
    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(buffer);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    memcpy(ImageBaseBuffer, buffer, pNt->OptionalHeader.SizeOfHeaders);

}

// 复制PE 结构节表
void CopyIamgeSection(PUCHAR buffer, PUCHAR ImageBaseBuffer)
{
    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(buffer);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {

        LOG_DEBUG("Section Name  %s\n", pSection->Name);

        memcpy(ImageBaseBuffer + pSection->VirtualAddress, buffer + pSection->PointerToRawData, pSection->SizeOfRawData);
        pSection++;
    }

}


#ifdef _WIN64
typedef ULONGLONG	QDWORD;
typedef PULONGLONG	PQDWORD;
#else
typedef DWORD	QDWORD;
typedef PDWORD	PQDWORD;
#endif

static BOOL DoRelocation(ULONG_PTR lpMemModule)
{
    PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
    PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);
    QDWORD dwDelta = (QDWORD)(lpMemModule - lpNtHeader->OptionalHeader.ImageBase);

    if (0 == dwDelta || 0 == lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        return TRUE;
    }

    DWORD dwRelocationOffset = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    PIMAGE_BASE_RELOCATION lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(lpMemModule + dwRelocationOffset);
    while (0 != lpBaseRelocation->VirtualAddress)
    {
        DWORD dwRelocationSize = (lpBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (DWORD i = 0; i < dwRelocationSize; i++)
        {
            WORD wRelocationValue = *((PWORD)(lpMemModule + dwRelocationOffset + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(WORD)));
            WORD wRelocationType = wRelocationValue >> 12;

            if (IMAGE_REL_BASED_DIR64 == wRelocationType && sizeof(PULONGLONG) == sizeof(PQDWORD))
            {
                PQDWORD lpAddress = (PQDWORD)(lpMemModule + lpBaseRelocation->VirtualAddress + (wRelocationValue & 4095));
                *lpAddress += dwDelta;
                //LOG_DEBUG("Relocation lpAddress  %I64X\n", lpAddress);
            }
            else if (IMAGE_REL_BASED_HIGHLOW == wRelocationType && sizeof(PDWORD) == sizeof(PQDWORD))
            {
                PQDWORD lpAddress = (PQDWORD)(lpMemModule + lpBaseRelocation->VirtualAddress + (wRelocationValue & 4095));
                *lpAddress += dwDelta;
                //LOG_DEBUG("Relocation lpAddress  %I64X\n", lpAddress);
            }
            else if (IMAGE_REL_BASED_ABSOLUTE != wRelocationType)
            {
                //LOG_DEBUG("Relocation lpAddress  End\n");
                return FALSE;
            }
        }

        dwRelocationOffset += lpBaseRelocation->SizeOfBlock;
        lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(lpMemModule + dwRelocationOffset);
    }

    return TRUE;
}


// 修复重定位
//VOID FixReloc(PUCHAR image) {
//
//
//    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
//    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)image);
//    PIMAGE_DATA_DIRECTORY pReloc = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
//    ULONG64 ImageBase = nt->OptionalHeader.ImageBase;
//    PIMAGE_BASE_RELOCATION relocAddr = (PIMAGE_BASE_RELOCATION)((ULONG64)image + pReloc->VirtualAddress);
//
//    while (relocAddr->VirtualAddress && relocAddr->SizeOfBlock) {
//
//        PUCHAR RelocBase = (PUCHAR)((ULONG64)image + relocAddr->VirtualAddress);
//        
//        ULONG BlockNum = relocAddr->SizeOfBlock / 2 - 4;
//        
//        for (ULONG i = 0; i < BlockNum; i++) {
//            ULONG64 Block = *(PUSHORT)((ULONG64)relocAddr + 8 + 2 * i);
//            ULONG64 high4 = Block & 0xF000;
//            ULONG64 low12 = Block & 0xFFF;
//            PULONG RelocAddr = (PULONG)((ULONGLONG)RelocBase + low12);
//            if (high4 == 0x3000) {
//                *RelocAddr = (ULONG)(*RelocAddr - ImageBase + (ULONGLONG)image);
//            }
//        }
//        relocAddr = (PIMAGE_BASE_RELOCATION)((ULONG64)relocAddr + relocAddr->SizeOfBlock);
//    }
//}

// 获取导出函数地址
PUCHAR GetExportFuncAddr(PUCHAR image, PUCHAR funcName)
{
    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(image);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    // 获取ImageBase
    ULONG64 imageBase = pNt->OptionalHeader.ImageBase;
    // 获取导出表
    PIMAGE_DATA_DIRECTORY pExportTable = (PIMAGE_DATA_DIRECTORY)(&(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
    // 获取导出表结构
    PIMAGE_EXPORT_DIRECTORY pExT =  (PIMAGE_EXPORT_DIRECTORY)(pExportTable->VirtualAddress + image);/////////////
    // 获取导出函数的总数
    ULONG numOfFunc = pExT->NumberOfFunctions;
    // 以名称导出的函数总数
    ULONG numOfFuncByName = pExT->NumberOfNames;
    // 函数地址表
    PULONG funcAddrTable = (PULONG)( pExT->AddressOfFunctions + image);
    // 函数名称地址表
    PULONG funcNameAddrTable = (PULONG) (pExT->AddressOfNames + image);
    // 函数序号的地址表
    PULONG funcOrdinalsAddrTable = (PULONG)(pExT->AddressOfNameOrdinals + image);
    // 循环遍历，获取对应函数的地址
    for (ULONG i = 0; i < numOfFuncByName; i++)
    {
        PUCHAR funcNameTemp = funcNameAddrTable[i] + image;
        if (strcmp(funcName, funcNameTemp) == 0)///////////
        {
            USHORT funcAddrIndex = *(USHORT*)((ULONG64)funcOrdinalsAddrTable + (i * 2));
            return funcAddrTable[funcAddrIndex] + image;
        }
    }
    return 0;
}

// 修复导入表

//#define NT_NAME "ntoskrnl.exe"



//DWORD RVAtoFOA(DWORD dwRVA)
//{
//    //此RVA落在哪个区段中
//    //找到所在区段后，
//    //减去所在区段的起始位置，加上在文件中的起始位置
//    //大文件头中找区段数
//    int nCountOfSection = g_pNt->FileHeader.NumberOfSections;
//    //区段表头
//    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);
//    //在扩展头中找到块对齐数
//    DWORD dwSecAligment = g_pNt->OptionalHeader.SectionAlignment;
//    //循环
//    for (int i = 0; i < nCountOfSection; i++)
//    {
//        //求在内存中的真实大小
//        //Misc.VirtualSize % dwSecAligment如果是0代表刚好对齐否则就先对齐（非0就是真）
//        //Misc.VirtualSize / dwSecAligment * dwSecAligment   + dwSecAligment     //最后加上余数的对齐
//        DWORD dwRealVirSize = pSec->Misc.VirtualSize % dwSecAligment ?
//            pSec->Misc.VirtualSize / dwSecAligment * dwSecAligment + dwSecAligment
//            : pSec->Misc.VirtualSize;
//        //区段中的相对虚拟地址转文件偏移  思路是 用要转换的地址与各个区
//        //段起始地址做比较如果落在一个区段中（大于起始地址小于起始地址加区段最大偏移和），
//        //就用要转换的相对虚拟地址减去区段的起始地址的相对虚拟地址，
//        //得到了这个地址相对这个区段偏移，再用得到的这个偏移加上区段在文件中的偏移的起始位置
//        //（pointerToRawData字段)就是他在文件中的文件偏移
//        if (dwRVA >= pSec->VirtualAddress &&
//            dwRVA < pSec->VirtualAddress + dwRealVirSize)
//        {
//            //FOA = RVA - 内存中区段的起始位置 + 在文件中区段的起始位置 
//            return dwRVA - pSec->VirtualAddress + pSec->PointerToRawData;
//        }
//        //下一个区段地址
//        pSec++;
//    }
//}




//void PrintResourceTable(PVOID pFileBuffer) {
//
//
//    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
//    PIMAGE_FILE_HEADER pImageFileHeader = NULL;
//    PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
//    PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
//    PIMAGE_SECTION_HEADER NewSec = NULL;
//
//    PIMAGE_RESOURCE_DIRECTORY pImageResourceDireOne = NULL;
//    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceEntryOne = NULL;
//
//    PIMAGE_RESOURCE_DIRECTORY pImageResourceDireTwo = NULL;
//    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceEntryTwo = NULL;
//
//
//    PIMAGE_RESOURCE_DIRECTORY pImageResourceDireThree = NULL;
//    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceEntryThree = NULL;
//
//    PIMAGE_DATA_DIRECTORY pImageDataDire = NULL;
//    PIMAGE_RESOURCE_DIR_STRING_U pDirString = NULL;
//
//    DWORD RVA = 0;
//    DWORD FOA = 0;
//    DWORD dwEntryNumOne = 0;
//    DWORD dwEntryNumTwo = 0;
//    DWORD dwEntryNumThree = 0;
//
//    DWORD i = 0;
//    DWORD j = 0;
//    DWORD k = 0;
//    DWORD m = 0;
//
//    pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
//    pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
//    pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
//    pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
//
//    RVA_TO_FOA(pFileBuffer, pImageOptionalHeader->DataDirectory[2].VirtualAddress, &FOA);
//    /*
//
//      typedef struct _IMAGE_RESOURCE_DIRECTORY {
//      DWORD   Characteristics;						//资源属性  保留 0
//      DWORD   TimeDateStamp;						//资源创建的时间
//      WORD    MajorVersion;						//资源版本号 未使用 0
//      WORD    MinorVersion;						//资源版本号 未使用 0
//      WORD    NumberOfNamedEntries;						//以名称命名的资源数量
//      WORD    NumberOfIdEntries;						//以ID命名的资源数量
//      //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
//      } IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
//    */
//
//    pImageResourceDireOne = (DWORD)pFileBuffer + (DWORD)FOA;
//    dwEntryNumOne = pImageResourceDireOne->NumberOfIdEntries + pImageResourceDireOne->NumberOfNamedEntries;
//    pImageResourceEntryOne = (DWORD)pImageResourceDireOne + 16;
//    for (i = 0; i < dwEntryNumOne; i++) {
//        if (pImageResourceEntryOne[i].NameIsString == 1) { // 1
//            pDirString = (PIMAGE_RESOURCE_DIR_STRING_U)pImageResourceEntryOne[i].NameOffset;
//            wprintf(L"第一层资源类型: %s\n", pDirString->NameString); // 第一层资源类型
//        }
//        else { //0 
//            printf("第一层资源类型: %d\n", pImageResourceEntryOne[i].NameOffset); // 第一层资源类型
//        }
//        //======================pImageResourceDireTwo=========================
//        pImageResourceDireTwo = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDireOne + (DWORD)pImageResourceEntryOne[i].OffsetToDirectory);
//        dwEntryNumTwo = pImageResourceDireTwo->NumberOfIdEntries + pImageResourceDireTwo->NumberOfNamedEntries;
//        pImageResourceEntryTwo = (DWORD)pImageResourceDireTwo + 16;
//        for (j = 0; j < dwEntryNumTwo; j++) {
//            if (pImageResourceEntryTwo[j].NameIsString == 1) { // 1
//                pDirString = (PIMAGE_RESOURCE_DIR_STRING_U)pImageResourceEntryTwo[j].NameOffset;
//                wprintf(L"\t第二层资源名称: %s\n", pDirString->NameString); // 第二层资源名称
//            }
//            else { //0 
//                printf("\t第二层资源名称: %d\n", pImageResourceEntryTwo[j].NameOffset); // 第二层资源名称
//            }
//
//            //======================pImageResourceDireThree=========================
//            pImageResourceDireThree = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDireOne + (DWORD)pImageResourceEntryTwo[j].OffsetToDirectory);
//            dwEntryNumThree = pImageResourceDireThree->NumberOfIdEntries + pImageResourceDireThree->NumberOfNamedEntries;
//            pImageResourceEntryThree = (DWORD)pImageResourceDireThree + 16;
//            for (k = 0; k < dwEntryNumThree; k++) {
//                if (pImageResourceEntryThree[k].NameIsString == 1) { // 1
//                    pDirString = (PIMAGE_RESOURCE_DIR_STRING_U)pImageResourceEntryThree[k].NameOffset;
//                    wprintf(L"\t\t第三层代码页编号: %s\n", pDirString->NameString); // 第三层代码页编号
//                }
//                else { //0 
//                    printf("\t\t第三层代码页编号: %d\n", pImageResourceEntryThree[k].NameOffset); // 第三层代码页编号
//                }
//
//                //======================IMAGE_RESOURCE_DATA_ENTRY=========================
//                //pImageDataDire IMAGE_RESOURCE_DATA_ENTRY
//                pImageDataDire = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pImageResourceDireOne + (DWORD)pImageResourceEntryThree[k].OffsetToDirectory);
//                printf("\t\t\t VirtualAddress: 0x%X, Size: 0x%X\n", pImageDataDire->VirtualAddress, pImageDataDire->Size);
//            }
//        }
//        printf("==================================\n");
//    }
//}


void FixResource(PUCHAR image) {

    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(image);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    // 获取导入表
    PIMAGE_DATA_DIRECTORY pImportTable = (PIMAGE_DATA_DIRECTORY)(&(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]));


    // 获取导入表结构
    PIMAGE_RESOURCE_DIRECTORY pRes = (PIMAGE_RESOURCE_DIRECTORY)(pImportTable->VirtualAddress + image);

    DWORD  DwCountOfResType = pRes->NumberOfIdEntries + pRes->NumberOfNamedEntries;

    LOG_DEBUG("pResEntry->NumberOfIdEntries  %d   pResEntry->NumberOfNamedEntries %d", pRes->NumberOfIdEntries, pRes->NumberOfNamedEntries);


    

    for (int i = 0; i < DwCountOfResType; i++)
    {   //pRes代表PIMAGE_RESOURCE_DIRECTORY的首地址+1之后就是后面的PIMAGE_RESOURCE_DIRECTORY_ENTRY首地址
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry =
            (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRes + 1);
        //typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
        //这个联合体说明资源叫什么  如果这种资源是已知的也就是微软定义的那么
        //联合体最高位为0也就是NameIsString成员为0这个时候整个四字节（union）代表着已知资源的类型，也就是ID起
        //作用  如果这种资源是未知是那么NameIsString的最高位为1 低31位指向一个name的结构体（PIMAGE_RESOURCE_DIR_STRING_U）偏移，也就是DWORD   Name;起作用
        //	union {
        //		struct {
        //			DWORD NameOffset : 31;
        //			DWORD NameIsString : 1;
        //		} DUMMYSTRUCTNAME;
        //		DWORD   Name;
        //		WORD    Id;
        //	} DUMMYUNIONNAME;
        //这个联合体说明资源在哪里
        //当DataIsDirectory字段为1时（也就是这个四字节最高位为1）说明这个联合体表示的地方是一个目录，OffsetToDirectory（低31位）表示具体有
        //多少个地方，这个些地方就是第二层
        //	union {
        //		DWORD   OffsetToData;
        //		struct {
        //			DWORD   OffsetToDirectory : 31;
        //			DWORD   DataIsDirectory : 1;
        //		} DUMMYSTRUCTNAME2;  
        //	} DUMMYUNIONNAME2;
        //} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

        //判断这种资源是字符串还是ID
        if (pResEntry->NameIsString)
        {
            //如果是字符串，NameOffset保存的就是这个字符串相对资源起始位置的偏移  
            //得到名字字符串的FOA
            DWORD64 dwName = (DWORD64)(pResEntry->NameOffset + (DWORD)pRes);
            //NameOffset所指向的结构体是IMAGE_RESOURCE_DIR_STRING_U类型
            //这里保存了字符串的长度和起始位置
            PIMAGE_RESOURCE_DIR_STRING_U pName = (PIMAGE_RESOURCE_DIR_STRING_U)dwName;
            //这里的字符串不是以0结尾的，所以需要拷贝出来加上‘\0’结尾后再打印
            //WCHAR* pResName = new wchar_t[pName->Length + 1]{};
            //memcpy(pResName, pName, (pName->Length) * sizeof(WCHAR));
            ////因为是WCHAR，所以用wprintf
            //wprintf(L"%s\n", pResName);
            ////释放内存
            //delete[] pResName;
        }
        else   //id
        {
            char* arryResType[] = { "", "鼠标指针（Cursor）", "位图（Bitmap）", "图标（Icon）", "菜单（Menu）"
                , "对话框（Dialog）", "字符串列表（String Table）", "字体目录（Font Directory）", "字体（Font）", "快捷键（Accelerators）"
                , "非格式化资源（Unformatted）", "消息列表（Message Table）", "鼠标指针组（Croup Cursor）", "", "图标组（Group Icon）", ""
                , "版本信息（Version Information）" };
            if (pResEntry->Id < 17)
            {
                LOG_DEBUG("arryResType[pResEntry->Id]  %s\n", arryResType[pResEntry->Id]);
            }
            else
            {
                LOG_DEBUG("pResEntry->Id %04X\n", pResEntry->Id);
            }

            //判断是否有下一层（0个表示没有下一层）
            if (pResEntry->DataIsDirectory)
            {   //到了第二层相对结构体同样和上一层一样但是OffsetToDirectory就指向对三层了
                DWORD64 dwResSecond = (DWORD64)pRes + pResEntry->OffsetToDirectory;
                PIMAGE_RESOURCE_DIRECTORY pResSecond = (PIMAGE_RESOURCE_DIRECTORY)dwResSecond;
                //第二层个数
                DWORD dwCountOfSecond =
                    pResSecond->NumberOfIdEntries + pResSecond->NumberOfNamedEntries;
                //遍历每一个资源
                for (int iSecond = 0; iSecond < dwCountOfSecond; iSecond++)
                {
                    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResSecondEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResSecond + 1);

                    //判断这种资源是字符串还是ID
                    if (pResEntry->NameIsString)
                    {
                        //如果是字符串，NameOffset保存的就是这个字符串的RVA
                        //得到名字字符串的FOA
                      //  DWORD dwNameFOA = (DWORD)(RVAtoFOA(pResEntry->NameOffset) + image);
                      // 
                       DWORD64 dwNameFOA = (DWORD64)(pResEntry->NameOffset + image);
                        //NameOffset所指向的结构体是IMAGE_RESOURCE_DIR_STRING_U类型
                        //这里保存了字符串的长度和起始位置
                        PIMAGE_RESOURCE_DIR_STRING_U pName = (PIMAGE_RESOURCE_DIR_STRING_U)dwNameFOA;
                        //这里的字符串不是以0结尾的，所以需要拷贝出来加上‘\0’结尾后再打印
                        //WCHAR* pResName = new WCHAR[pName->Length + 1]{};
                        //memcpy(pResName, pName, (pName->Length) * sizeof(WCHAR));
                        //wprintf(L"pResName %s\n", pResName);
                        //delete[] pResName;
                        LOG_DEBUG("dwNameFOA  %I64X\n", dwNameFOA);
                    }
                    else   //id
                    {
                        LOG_DEBUG("pResEntry->Id %04X\n", pResEntry->Id);
                    }
                    //判断有没有下一层
                    //第三层  同样套路从第一个结构体开始找 到了OffsetToDirectory就是第三层了
                    //这里要注意的是到了第三层这个IMAGE_RESOURCE_DIRECTORY_ENTRY结构体的第一个联合体就没用了
                    //同时第二个联合体的DataIsDirectory为0没有下一层了 
                    //通过OffsetToData字段找到资源结构体的偏移（指向_IMAGE_RESOURCE_DATA_ENTRY结构体）
                    if (pResSecondEntry->DataIsDirectory)
                    {
                        //第三层的起始位置
                        DWORD64 dwResThrid =
                            (DWORD64)pRes + pResSecondEntry->OffsetToDirectory;
                        PIMAGE_RESOURCE_DIRECTORY pResThrid = (PIMAGE_RESOURCE_DIRECTORY)dwResThrid;

                        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResThridEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResThrid + 1);
                        //第三层，已经是最后一层，使用PIMAGE_RESOURCE_DIRECTORY_ENTRY中的
                        //OffsetToData成员，得到PIMAGE_RESOURCE_DATA_ENTRY结构的位置
                        /*typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
                        DWORD   OffsetToData;   //资源偏移
                        DWORD   Size;
                        DWORD   CodePage;
                        DWORD   Reserved;
                        } IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
                        */
                        PIMAGE_RESOURCE_DATA_ENTRY pResData =
                            (PIMAGE_RESOURCE_DATA_ENTRY)(pResThridEntry->OffsetToData + (DWORD)pRes);
                        //资源的RVA和Size
                        DWORD dwResDataRVA = pResData->OffsetToData;
                        DWORD dwResDataSize = pResData->Size;
                        //PIMAGE_RESOURCE_DATA_ENTRY中的OffsetToData是个RVA
                        DWORD64 dwResDataFOA = (DWORD64)(dwResDataRVA + image);
                        //资源的二进制数据
                        //遍历打印资源的二进制数据  这里就只能是二进制了
                        PBYTE pData = (PBYTE)dwResDataFOA;
                        for (int iData = 0; iData < dwResDataSize; iData++)
                        {
                            if (iData % 16 == 0 && iData != 0)
                            {
                                //printf("\n");
                            }
                            LOG_DEBUG("%02X ", pData[iData]);
                        }
                      //  printf("\n");
                    }
                    //下一个资源
                    pResSecondEntry++;
                }
            }
        }
        //下一种资源
        pResEntry++;
    }








    //IMAGE_RESOURCE_DIRECTORY_ENTRY


}

VOID FixImport(PUCHAR image)
{
    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(image);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    // 获取导入表
    PIMAGE_DATA_DIRECTORY pImportTable = (PIMAGE_DATA_DIRECTORY)(&(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
    // 获取导入表结构
    PIMAGE_IMPORT_DESCRIPTOR pImportEntry = (PIMAGE_IMPORT_DESCRIPTOR)(pImportTable->VirtualAddress + image);

    // 遍历导入表
    while (pImportEntry->Name)
    {
        // 模块基地址
        ULONG64 moduleBase = 0;
        // 返回模块大小


        ULONG64 moduleSize = QuerySysModule(pImportEntry->Name + image, &moduleBase);
        if (moduleSize)
        {
            // 输入表IAT 地址
            PULONG64 pIAT = (PULONG64)(pImportEntry->FirstThunk + image);
            while (*pIAT)
            {
                // 导入函数的名称
                PIMAGE_IMPORT_BY_NAME funcName = (PIMAGE_IMPORT_BY_NAME)(*pIAT + image);
                // 获取函数地址
                ULONG64 FuncAddr = (ULONG64)GetExportFuncAddr((PUCHAR)moduleBase, funcName->Name);
                // 修复IAT
               // LOG_DEBUG("FuncAddr ==  %s   %s   %I64X\n", pImportEntry->Name + image, funcName->Name, FuncAddr);


                *pIAT = FuncAddr;
                pIAT++;
            }
        }
        pImportEntry++;
    }

}



_Kernel_entry_ PVOID NTAPI RtlImageDirectoryEntryToData(PVOID Base, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);

// 内存加载驱动文件（加载PE）


extern PVOID  LoadMemoryToUser(PMDL* pMdl, PVOID addr, DWORD nSize, KPROCESSOR_MODE Mode, ULONG Protect);




//映射镜像物理地址
NTSTATUS(*MiMapSystemImage)(PVOID PSECTION, PUCHAR BaseVa, BOOLEAN Bren);

NTSTATUS(*MiMapSystemImageLow)(PVOID PSECTION, PUCHAR BaseVa);

//_Kernel_entry_ NTSTATUS MmLoadSystemImage(PUNICODE_STRING Imagepath,
//    DWORD64 prefix , 
//    DWORD64 basename,
//    DWORD64 A, 
//    DWORD64 B, 
//    DWORD64 C);


extern ULONGLONG _CODE_GET_REAL_ADDRESS_0(char* pEl, int nCodeSize);

extern ULONGLONG _CODE_GET_REAL_ADDRESS(char* pEl);

extern char* _ASM_GET_CALL(char* pAdr, int num);


extern PVOID  LoadMemoryUserToKernel(PMDL* pMdl, PVOID addr, DWORD nSize, ULONG Protect);


extern void GetBasePTE();

#include "SSDT_NEW_FUN.h"
#include "PhysicalMemory.h"
#include "SYSTEM_MODULE_STRUCT.h"


NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

ULONG64 LoadDriverFromFile(PUCHAR buffer, PUNICODE_STRING uString, PULONG64 pEntry, DWORD64* nSize, DWORD64* hAttchModDriver){

    PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader((PVOID)((ULONGLONG)buffer & 0xFFFFFFFFFFFFFFFC));
    if (pNtHeader)
    {
       USHORT nVer = pNtHeader->OptionalHeader.MajorSubsystemVersion;
       OBJECT_ATTRIBUTES ObjectAttributes = {0};

       InitializeObjectAttributes(&ObjectAttributes, uString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);
       HANDLE FileHandle;
       IO_STATUS_BLOCK IoStatusBlock;
       NTSTATUS  status = ZwCreateFile(&FileHandle, 0x80000000, &ObjectAttributes, &IoStatusBlock, 0, 0, 5, 1, 0, 0, 0);

       if (!NT_SUCCESS(status)){
           LOG_DEBUG("error %08X\n ", status);
           return 0;
       }

       InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);

       HANDLE SectionHandle = 0;
       LARGE_INTEGER MaximumSize = {0};

       status = ZwCreateSection(
           &SectionHandle,
           0xF0005u,
           &ObjectAttributes,
           &MaximumSize,
           nVer < 6u ? 8 : 2,
           0x8000000u,
           FileHandle);

      // STATUS_FILE_LOCK_CONFLICT

       if (!NT_SUCCESS(status)) {
           LOG_DEBUG("error %08X\n ", status);
           return 0;
       }
       HANDLE Object = 0;
       status = ObReferenceObjectByHandle(SectionHandle, 0, 0, 0, &Object, 0);
       ZwClose(SectionHandle);


       if (!NT_SUCCESS(status)) {
           LOG_DEBUG("error %08X\n ", status);
           return 0;
       }


       PVOID MappedBase = 0;
       SIZE_T ViewSize = 0;

       //MiMapImageInSystemSpace
       status = MmMapViewInSystemSpace(Object, &MappedBase, &ViewSize);


       if (!NT_SUCCESS(status)) {
           LOG_DEBUG("error %08X\n ", status);
           return 0;
       }


       *nSize = ViewSize;



       PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader(MappedBase);

       //PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(MappedBase);
       // NT 头
       //PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((char *)MappedBase + pDos->e_lfanew);
       // 入口点
       *pEntry = (ULONG64)(pNtHeader->OptionalHeader.AddressOfEntryPoint + (char*)MappedBase);


       return MappedBase;

    }
    return 0;
}



ULONG64 LoadDriver(PUCHAR buffer, PULONG64 pEntry, DWORD64* nSize, DWORD64* hAttchModDriver)
{

    GetBasePTE();

    //RtlImageNtHeader

    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(buffer);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    // 申请内存
    PHYSICAL_ADDRESS phyLow;
    PHYSICAL_ADDRESS phyHigh;
    // 声明申请内存的物理页所在的范围为0x0-0xFFFFFFFF
    phyLow.QuadPart = 0; // 0
    phyHigh.QuadPart = 0x00FFFFFF;; // FFFFFFFF
    PUCHAR image = NULL;
    int count = 3;

    PVOID hMod = 0;
    PVOID hNewMod = 0;
    do
    {
        // 进行多次申请，保证内存一定能被申请到
        PVOID imageV = MmAllocateContiguousMemorySpecifyCache(
            pNt->OptionalHeader.SizeOfImage, // 申请内存的大小
            phyLow, // 范围起点
            phyHigh, // 范围终点
            phyLow, // 
            MmCached);// 缓冲类型

 


        //MmMapViewInSystemSpace()


        if (imageV)
        {

            //int NeedPageSize = (pNt->OptionalHeader.SizeOfImage / PAGE_SIZE) + 1;

            //FindZeroMemory(NeedPageSize, &hMod, &hNewMod);

            //LOG_DEBUG("FindZeroMemory <%p><%p> \n", hMod, hNewMod);

            //PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(imageV);

            //ULONGLONG Number = ((ULONGLONG)phyAddress.QuadPart) >> 12;

            //LOG_DEBUG("FindZeroMemory <%p><%p>  phyAddress <%p> Number<%p>\n", hMod, hNewMod, phyAddress.QuadPart, Number);
            //if (hMod == 0 || hNewMod == 0) {
            //    LOG_DEBUG("hMod :<%p> hNewMod<%p>\n", hMod, hNewMod);
            //    return 0;
            //}
            //if (hMod != 0 && hNewMod != 0)
            //{
            //    LOG_DEBUG("hMod :<%p> hNewMod<%p>  PageSize:<%d>\n", hMod, hNewMod, pNt->OptionalHeader.SizeOfImage / PAGE_SIZE);
            //    // return 0;

            //    //DWORD64 PLM4[4] = { 0 };
            //    //MiFillPteHierarchy(hMod, PLM4);

            //    //for (size_t i = 4; i > 0; --i) {

            //    //    MMPTE pNewI = *(MMPTE*)PLM4[i];


            //    //    LOG_DEBUG("PLM4:%d Valid:%d Writable:%d Owner:%d WriteThrough:%d CacheDisable:%d Accessed:%d Dirty:%d LargePage:%d Global:%d CopyOnWrite:%d Prototype:%d Write:%d PageFrameNumber:%08X NoExecute:%d \n", i, pNewI.u.Hard.Valid,
            //    //        pNewI.u.Hard.Writable,
            //    //        pNewI.u.Hard.Owner,
            //    //        pNewI.u.Hard.WriteThrough,
            //    //        pNewI.u.Hard.CacheDisable,
            //    //        pNewI.u.Hard.Accessed,
            //    //        pNewI.u.Hard.Dirty,
            //    //        pNewI.u.Hard.LargePage,
            //    //        pNewI.u.Hard.Global,
            //    //        pNewI.u.Hard.CopyOnWrite,
            //    //        pNewI.u.Hard.Prototype,
            //    //        pNewI.u.Hard.Write,
            //    //        pNewI.u.Hard.PageFrameNumber,
            //    //        pNewI.u.Hard.NoExecute);

            //    //    LOG_DEBUG("PLM4:%d reserved1:%d SoftwareWsIndex:%d\n", i, pNewI.u.Hard.reserved1, pNewI.u.Hard.SoftwareWsIndex);

            //    //    if (pNewI.u.Hard.LargePage == 1)
            //    //    {
            //    //        break;
            //    //    }

            //    //}



            //    for (size_t i = 0; i < NeedPageSize; i++){

            //        ULONGLONG Ptr = (ULONGLONG)hNewMod + i * PAGE_SIZE;
            //        SetAddressTlb(Ptr, Number + i, hMod);

            //      //  LOG_DEBUG("SetAddressTlb Iter :<%p> <%p>\n", Ptr, Number + i);

            //        char MemBuffer[PAGE_SIZE] = { 0 };

            //        __try {
            //            RtlCopyMemory(MemBuffer, Ptr, PAGE_SIZE);

            //        //   // RtlZeroMemory(Ptr, PAGE_SIZE);

            //        }
            //        __except (1) {
            //            LOG_DEBUG("SetAddressTlb Error\n");
            //        }

            //    }
            //    
            //    //KIRQL irql = __readcr8();
            //    //__writecr8(0xC);
            //    //__writecr3(__readcr3());
            //    //__writecr8(irql);

            //}

            //image = hNewMod;
            //*hAttchModDriver = hMod;


  


            //image = hNewMod;
            //*hAttchModDriver = hMod;
            
            //LOG_DEBUG("MmAllocateContiguousMemorySpecifyCache <%p> phy<%p> \n", imageV, phyAddress.QuadPart);
            //image = imageV;
            PMDL  pMdl = 0;  //ULONG_PTR kernelBase
            image = LoadMemoryUserToKernel(&pMdl, imageV, pNt->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
            if (image)
            {
                RtlZeroMemory(image, pNt->OptionalHeader.SizeOfImage);

            }
            break;
        }
        --count;
    } while (count);

    if (!image)
    {
        return 0;
    }

    //PMDL pMdl = IoAllocateMdl(image, pNt->OptionalHeader.SizeOfImage, FALSE, FALSE, NULL);

    //__try
    //{
    //    MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
    //}
    //__except(1) {

    //    LOG_DEBUG("MmProbeAndLockPages  %08X", GetExceptionCode());
    //    return STATUS_UNSUCCESSFUL;
    //}

    //NTSTATUS status = MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE);

    //if (!NT_SUCCESS(status))
    //{
    //    LOG_DEBUG("MmProtectMdlSystemAddress  %08X", status);
    //    return STATUS_UNSUCCESSFUL;
    //}

    // 拷贝头部
    CopyIamgeHeader(buffer, image);
    CopyIamgeSection(buffer, image);
    DoRelocation(image);
    FixImport(image);


    //FixResource(image);

    


    // IMAGE_DIRECTORY_ENTRY_RESOURCE

    // 拿到DOS 头
    pDos = (PIMAGE_DOS_HEADER)(image);
    // NT 头
    pNt = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);
    // 入口点
    *pEntry = (ULONG64)(pNt->OptionalHeader.AddressOfEntryPoint + image);



    if ((pNt->OptionalHeader.DllCharacteristics & 0x2000) == 0) {
        LOG_DEBUG(" pNt->OptionalHeader.DllCharacteristics  %08X", pNt->OptionalHeader.DllCharacteristics);
    }
    LOG_DEBUG(" pNt->OptionalHeader.DllCharacteristics  %08X", pNt->OptionalHeader.DllCharacteristics);
        //v17->Flags |= 2u;

    //DriverEntryCallBack entryCallBack = (DriverEntryCallBack)(pNt->OptionalHeader.AddressOfEntryPoint + image);

    //ULONG size = 0;

    //PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfigDir = RtlImageDirectoryEntryToData(image, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);
    //// 修改cookie
    //pLoadConfigDir->SecurityCookie |= 0x12123;


    *nSize = pNt->OptionalHeader.SizeOfImage;

    return (ULONG64)image;
}


NTKERNELAPI POBJECT_TYPE MmSectionObjectType;










PVOID AllocMemoryWithMmMap(DWORD64 nSize, PVOID* pSectionObject) {

    HANDLE SectionHandle;
    PVOID SectionObject = NULL;
    PVOID MappingAddress = 0;
    SIZE_T MappingSize = 0;
    LARGE_INTEGER MaximumSize = { 0 };
    MaximumSize.QuadPart = nSize;

    NTSTATUS status = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

  //  LOG_DEBUG("ZwCreateSection  %08X\n", status);

    if (!NT_SUCCESS(status)){
        LOG_DEBUG("ZwCreateSection  %08X\n", status);
        return 0;
    }


    status = ObReferenceObjectByHandle(SectionHandle, SECTION_ALL_ACCESS, MmSectionObjectType, KernelMode, &SectionObject, NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(SectionHandle);
        LOG_DEBUG("ObReferenceObjectByHandle  %08X\n", status);
        return 0;
    }

    //映射到session空间
   // MmMapViewInSessionSpace(SectionObject, &MappingAddress, &MappingSize);
   // LOG_DEBUG("ObReferenceObjectByHandle  %08X\n", status);
    status = MmMapViewInSystemSpace(SectionObject, &MappingAddress, &MappingSize);//MmMapViewInSessionSpace //MmMapViewInSystemSpace
    if (!NT_SUCCESS(status)) {
        LOG_DEBUG("MmMapViewInSystemSpace  %08X\n", status);
        return 0;
    }
    *pSectionObject = SectionObject;
    return MappingAddress;

}


ULONG64 _LoadDriverW(PUCHAR buffer, PULONG64 pEntry, DWORD64* nSize, PLDR_DATA_TABLE_ENTRY Ldr, PVOID * pSectionObject)
{

    GetBasePTE();

    //RtlImageNtHeader

    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(buffer);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    // 申请内存
    PHYSICAL_ADDRESS phyLow;
    PHYSICAL_ADDRESS phyHigh;
    // 声明申请内存的物理页所在的范围为0x0-0xFFFFFFFF
    phyLow.QuadPart = 0; // 0
    phyHigh.QuadPart = 0x00FFFFFF;; // FFFFFFFF
    PUCHAR image = NULL;
    int count = 3;

    PVOID hMod = 0;
    PVOID hNewMod = 0;



    HANDLE SectionHandle;
    PVOID SectionObject = NULL;


    //AllocMemoryWithMmMap
    image = AllocMemoryWithMmMap(pNt->OptionalHeader.SizeOfImage, &SectionObject);

    //STATUS_ABANDONED

    if (!image)
    {
        return 0;
    }

    RtlZeroMemory(image, pNt->OptionalHeader.SizeOfImage);

    *pSectionObject = SectionObject;

    // 拷贝头部
    RtlCopyMemory(image, Ldr->DllBase, pNt->OptionalHeader.SizeOfImage);
    CopyIamgeHeader(buffer, image);
    CopyIamgeSection(buffer, image);
    DoRelocation(image);
    FixImport(image);


    // FixResource(image);

   //  RtlCopyMemory(image, Ldr->DllBase, pNt->OptionalHeader.SizeOfImage);

     // IMAGE_DIRECTORY_ENTRY_RESOURCE

    pDos = (PIMAGE_DOS_HEADER)(image);
    // NT 头
    pNt = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);
    // 入口点
    *pEntry = (ULONG64)(pNt->OptionalHeader.AddressOfEntryPoint + image);

    if ((pNt->OptionalHeader.DllCharacteristics & 0x2000) == 0) {
        LOG_DEBUG(" pNt->OptionalHeader.DllCharacteristics  %08X", pNt->OptionalHeader.DllCharacteristics);
    }
    LOG_DEBUG(" pNt->OptionalHeader.DllCharacteristics  %08X", pNt->OptionalHeader.DllCharacteristics);
    //v17->Flags |= 2u;



    *nSize = pNt->OptionalHeader.SizeOfImage;

    return (ULONG64)image;
}


ULONG64 LoadDriverV(PUCHAR buffer, PULONG64 pEntry, DWORD64* nSize, PLDR_DATA_TABLE_ENTRY Ldr, PVOID* pSectionObject) {

   // DWORD64 hAttch = 0;
    ULONG64 hMod = _LoadDriverW(buffer, pEntry, nSize, Ldr, pSectionObject);
    return hMod;
}



PVOID  CreateImageSection(PUNICODE_STRING ImagePath) {



    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(
        &ObjectAttributes,
        ImagePath,
        (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
        NULL,
        NULL);

    HANDLE FileHandle = 0;
    HANDLE SectionHandle = 0;
    PVOID ViewBase = NULL;
    ULONGLONG ViewSize = 0;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    NTSTATUS Status = ZwOpenFile(
        &FileHandle,
        FILE_EXECUTE,
        &ObjectAttributes,
        &IoStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        0);

    if (NT_SUCCESS(Status)) {
        InitializeObjectAttributes(
            &ObjectAttributes,
            NULL,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        Status = ZwCreateSection(
            &SectionHandle,
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            &ObjectAttributes,
            NULL,
            PAGE_EXECUTE,
            0x1000000, // SEC_IMAGE
            FileHandle);

        if (NT_SUCCESS(Status)) {
            Status = ZwMapViewOfSection(
                SectionHandle,
                ZwCurrentProcess(),
                &ViewBase,
                0L,
                0L,
                NULL,
                &ViewSize,
                ViewShare,
                0L,
                PAGE_EXECUTE);

            if (NT_SUCCESS(Status)) {





            }
        }
    }


    return 0;
}







ULONG64 LoadDriverSection(PVOID DriverSection, PUCHAR buffer, PULONG64 pEntry, DWORD64* nSize)
{

    UNICODE_STRING uString;
    RtlInitUnicodeString(&uString, L"MmLoadSystemImage");
    char* _MmLoadSystemImage = MmGetSystemRoutineAddress(&uString);

    if (_MmLoadSystemImage == 0)
    {
        LOG_DEBUG("_MmLoadSystemImage == 0");
        return 0;
    }

    char* MmLoadSystemImageEx = _CODE_GET_REAL_ADDRESS((_ASM_GET_CALL(_MmLoadSystemImage, 1)));



    RTL_OSVERSIONINFOEXW OsVersion = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;
    OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
    Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);

    //if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362)
    //{

    //}



    if (OsVersion.dwBuildNumber > 19041)
    {
        MiMapSystemImage = _CODE_GET_REAL_ADDRESS((_ASM_GET_CALL(MmLoadSystemImageEx, 15)));
        MiMapSystemImageLow = 0;
        LOG_DEBUG("MiMapSystemImage  %I64X", MiMapSystemImage);
    }
    else
    {
        MiMapSystemImageLow = _CODE_GET_REAL_ADDRESS((_ASM_GET_CALL(MmLoadSystemImageEx, 13)));
        MiMapSystemImage = 0;
        LOG_DEBUG("MiMapSystemImageLow  %I64X", MiMapSystemImageLow);
        
    }


    //RtlImageNtHeader

    // 拿到DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(buffer);
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // 节表
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    // 申请内存
    PHYSICAL_ADDRESS phyLow;
    PHYSICAL_ADDRESS phyHigh;
    // 声明申请内存的物理页所在的范围为0x0-0xFFFFFFFF
    phyLow.QuadPart = 0; // 0
    phyHigh.QuadPart = 0x00FFFFFF; // FFFFFFFF
    PUCHAR image = NULL;
    int count = 3;
    do
    {
        // 进行多次申请，保证内存一定能被申请到
        PVOID imageV = MmAllocateContiguousMemorySpecifyCache(
            pNt->OptionalHeader.SizeOfImage, // 申请内存的大小
            phyLow, // 范围起点
            phyHigh, // 范围终点
            phyLow, // 
            MmCached);// 缓冲类型
        if (imageV)
        {
            PMDL  pMdl = 0;
            image = LoadMemoryToUser(&pMdl, imageV, pNt->OptionalHeader.SizeOfImage, KernelMode, PAGE_EXECUTE_READWRITE);
            if (image)
            {
                RtlZeroMemory(image, pNt->OptionalHeader.SizeOfImage);
            }
            break;
        }
        --count;
    } while (count);

    if (!image)
    {
        return STATUS_UNSUCCESSFUL;
    }



    //return;

    //if (MiMapSystemImageLow != 0){
    //    KIRQL OldIrql = 0;
    //    KeRaiseIrql(1, &OldIrql);
    //    Status = MiMapSystemImageLow(DriverSection, image);

    //    KeLowerIrql(OldIrql);
    //    LOG_DEBUG("MiMapSystemImageLow  Status %08X", Status);
    //}
    //else if (MiMapSystemImage != 0) {

    //    KIRQL OldIrql = 0;
    //    KeRaiseIrql(1, &OldIrql);
    //    Status = MiMapSystemImage(DriverSection, image, 0);

    //    KeLowerIrql(OldIrql);
    //    LOG_DEBUG("MiMapSystemImage  Status %08X", Status);
    //}

    // 拷贝头部
    //CopyIamgeHeader(buffer, image);
    //CopyIamgeSection(buffer, image);
    //FixReloc(image);
    //FixImport(image);
    //FixResource(image);




    // IMAGE_DIRECTORY_ENTRY_RESOURCE

    // 拿到DOS 头
    pDos = (PIMAGE_DOS_HEADER)(image);
    // NT 头
    pNt = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);
    // 入口点
    *pEntry = (ULONG64)(pNt->OptionalHeader.AddressOfEntryPoint + image);
    //DriverEntryCallBack entryCallBack = (DriverEntryCallBack)(pNt->OptionalHeader.AddressOfEntryPoint + image);

    //ULONG size = 0;

    //PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfigDir = RtlImageDirectoryEntryToData(image, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);
    //// 修改cookie
    //pLoadConfigDir->SecurityCookie |= 0x12123;


    *nSize = pNt->OptionalHeader.SizeOfImage;

    return (ULONG64)image;
}