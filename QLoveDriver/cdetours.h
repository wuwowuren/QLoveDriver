
#pragma once


#include <ntddk.h>


//PVOID  DetourCopyInstruction( PVOID pDst,
//     PVOID* ppDstPool,
//     PVOID pSrc,
//     PVOID* ppTarget,
//     LONG* plExtra);




 PVOID DetourCopyInstruction(PVOID pDst, PVOID* ppDstPool, PVOID pSrc, PVOID* ppTarget, LONG* plExtra);


 int DetourGetInstructionLength(PVOID ControlPc);
