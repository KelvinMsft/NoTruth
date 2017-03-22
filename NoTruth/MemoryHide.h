// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to shadow hook functions.

#ifndef NoTruth_MemoryHide_H_
#define NoTruth_MemoryHide_H_

#include <fltKernel.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//
//struct HideInformation;
struct EptData;
struct HiddenData;
struct ShareDataContainer;
// Expresses where to install KernelModeList by a function name, and its handlers
struct ShadowHookTarget {
  UNICODE_STRING target_name;  // An export name to hook
  void* handler;               // An address of a hook handler

  // An address of a trampoline code to call original function. Initialized by
  // a successful call of ShInstallHide().
  void* original_call;
};



////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    HiddenData* TruthAllocateHiddenData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void TruthFreeHiddenData(_In_ HiddenData* sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    ShareDataContainer* TruthAllocateSharedDataContainer();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void TruthFreeSharedHiddenData(
	_In_ ShareDataContainer* shared_sh_data);
   
_IRQL_requires_min_(DISPATCH_LEVEL) void ShHandleMonitorTrapFlag(
    _In_ HiddenData* sh_data,
    _In_ ShareDataContainer* shared_sh_data, _In_ EptData* ept_data);

//-------------------------------------------------------------------------------------------------------------------------------------

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C bool TruthCreateNewHiddenNode(
	_In_ ShareDataContainer* shared_sh_data,
	_In_ void* address, 
	_In_ const char* name, 
	_In_ ULONG64 P_Paddr,
	_In_ ULONG64 CR3,
	_In_ PVOID64 mdl,
	_In_ PEPROCESS proc);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS kStartHiddenEngine();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS kStopHiddenEngine();

_IRQL_requires_min_(DISPATCH_LEVEL) bool kHandleEptViolation(
	_In_ HiddenData* sh_data,
	_In_ ShareDataContainer* shared_sh_data, 
	_In_ EptData* ept_data,
	_In_ void* fault_va,
	_In_ void* fault_pa,
	_In_ bool  isExecute,
	_In_ bool  IsWrite,
	_In_ bool  IsRead); 

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS kDisableHideByProcess(
	PEPROCESS proc);

_IRQL_requires_min_(DISPATCH_LEVEL) void kEnableAllMemoryHide(
	_In_ HiddenData* data,
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data);


_IRQL_requires_min_(DISPATCH_LEVEL) void kDisableSingleMemoryHide(
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data,
	_In_ PEPROCESS proc
);

_Use_decl_annotations_ void kRemoveSingleHideNode(
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data,
	_In_ PEPROCESS proc
);

_IRQL_requires_min_(DISPATCH_LEVEL) void kDisableAllMemoryHide(
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data);

_Use_decl_annotations_ void kRemoveAllHideNode(
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data
);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C PMDLX GetHideMDL(
	_In_ ShareDataContainer* shared_sh_data, 
	_In_ PEPROCESS proc);
 
////////////////////////////////////////////////////////////////////////////////
//
// variables
//
////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // NoTruth_MemoryHide_H_
