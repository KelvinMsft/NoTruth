// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to NoTruth functions.

#ifndef NoTruth_NoTruth_H_
#define NoTruth_NoTruth_H_

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

#define IOCTL_HIDE_ADD				CTL_CODE_HIDE(1)			//初始化
#define IOCTL_HIDE_START			CTL_CODE_HIDE(2)			//初始化
#define IOCTL_HIDE_STOP				CTL_CODE_HIDE(3)			//初始化

////////////////////////////////////////////////////////////////////////////////
//
// types
//


struct ShareDataContainer;

extern ShareDataContainer* sharedata;
////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS NoTruthInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void NoTruthTermination();
  
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS AddMemoryHide(
	PEPROCESS proc, 
	ULONG64 address
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS StartMemoryHide();
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS  StopMemoryHide();
////////////////////////////////////////////////////////////////////////////////
//
// variables
//
////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // NoTruth_NoTruth_H_
