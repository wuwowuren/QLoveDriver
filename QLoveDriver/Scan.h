/*
*
* Copyright (c) 2015 - 2021 by blindtiger. All rights reserved.
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. SEe the License
* for the specific language governing rights and limitations under the
* License.
*
* The Initial Developer of the Original Code is blindtiger.
*
*/

#ifndef _SCAN_H_
#define _SCAN_H_

typedef signed __int8 s8, * s8ptr;
typedef signed __int16 s16, * s16ptr;
typedef signed __int32 s32, * s32ptr;
typedef signed __int64 s64, * s64ptr;

typedef unsigned __int8 u8, * u8ptr;
typedef unsigned __int16 u16, * u16ptr;
typedef unsigned __int32 u32, * u32ptr;
typedef unsigned __int64 u64, * u64ptr;

typedef void* ptr;

typedef unsigned char c, * cptr;
typedef unsigned __int16 wc, * wcptr;
typedef unsigned __int8 b, * bptr;


typedef __int64 s, * sptr;
typedef unsigned __int64 u, * uptr;

#ifdef __cplusplus
/* Assume byte packing throughout */
extern "C" {
#endif	/* __cplusplus */



    ptr
        ScanBytes(
             u8ptr Begin,
             u8ptr End,
			 u8ptr Sig
        );

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_SCAN_H_
