#pragma once

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>





NTSTATUS
NTAPI
LoadKernelImage(
	__in PWSTR ImageFileName,
	__in PWSTR ServiceName
);

NTSTATUS
NTAPI
UnloadKernelImage(
	__in PWSTR ServiceName
);