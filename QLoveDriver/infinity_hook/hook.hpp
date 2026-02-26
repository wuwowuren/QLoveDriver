#pragma once
#include <ntifs.h>

// 回调函数
typedef void(__fastcall* INFINITYHOOKCALLBACK)( unsigned int SystemCallIndex, void** SystemCallFunction);

// 初始化数据
bool IfhInitialize2(INFINITYHOOKCALLBACK fptr);

// 反初始化数据
bool IfhRelease2();