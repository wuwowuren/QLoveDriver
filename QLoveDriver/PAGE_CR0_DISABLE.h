#pragma once

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>



//关闭页面保护
KIRQL WPOFFx64();

//页面保护还原
void WPONx64(KIRQL irql);