// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to DdiMon functions.

#ifndef DDIMON_DDI_MON_H_
#define DDIMON_DDI_MON_H_

#include <fltKernel.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

#define FILE_DEVICE_HIDE	0x8000

#define IOCTL_BASE	0x800

#define CTL_CODE_HIDE(i)	\
	CTL_CODE(FILE_DEVICE_HIDE, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HIDE				CTL_CODE_HIDE(1)			//≥ı ºªØ
////////////////////////////////////////////////////////////////////////////////
//
// types
//


struct SharedShadowHookData;

extern SharedShadowHookData* sharedata;
////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS
    DdimonInitialization(_In_ SharedShadowHookData* shared_sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void DdimonTermination();

typedef struct HideInputInfo{
	PVOID	  hiddenAddr;
	PEPROCESS proc;
}HIDEINPUTINFO, *PHIDEINPUTINFO;

VOID HiddenStartByIOCTL(PEPROCESS proc, ULONG64 address);
////////////////////////////////////////////////////////////////////////////////
//
// variables
//
////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // DDIMON_DDI_MON_H_
