// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements shadow hook functions.

#include "MemoryHide.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <memory>
#include <algorithm>
#include <array>
#include "Ring3Hide.h"
#include <string>
#include <stack>
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

// Copy of a page seen by a guest as a result of memory shadowing
struct Page {
  UCHAR* page;  // A page aligned copy of a page
  Page();
  ~Page();
};


// Data structure shared across all processors
struct ShareDataContainer {
  std::vector<std::unique_ptr<HideInformation>> UserModeList; //var hide
  KSPIN_LOCK		  SpinLock;
  KLOCK_QUEUE_HANDLE LockHandle;
};

// Data structure for each processor
struct HiddenData {
  const HideInformation* UserModeBackup;   // remember which var hit the last 
}; 

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static HideInformation* TruthFindHideInfoByPhyAddr(
	const ShareDataContainer* shared_sh_data, ULONG64 fault_pa);
 
//Come from Reading, independent page
static void TruthEnableEntryForExecuteOnly(_In_ const HideInformation& info, _In_ EptData* ept_data);

//Come from Reading, independent page
static void TruthEnableEntryForReadOnly(_In_ const HideInformation& info, _In_ EptData* ept_data);

//Come from Write,  reset page for exec. and shared page with exec.
static void TruthEnableEntryForAll(_In_ const HideInformation& info , _In_ EptData* ept_data);

//Come from execute, reset page for exec. and shared page with write.
//static void K_EnableVarHidingForExec(_In_ const HideInformation& info, _In_ EptData* ept_data);

// After MTF used to reset a page for read-only ( because at most of case, 
// After write AND others read it which is unexpected case 
// As a result, we always have to set it to read-only, 
// so that we can confirm that CPU always used safe-page even after specific write / execute 
static const HideInformation* TruthRestoreLastHideInfo(_In_ HiddenData* sh_data);

static void TruthDisableVarHiding(_In_ const HideInformation& info,
								_In_ EptData* ept_data);

static void TruthSetMonitorTrapFlag(_In_ HiddenData* sh_data,
                                  _In_ bool enable);

static void TruthSaveLastHideInfo(_In_ HiddenData* sh_data,
								_In_ const HideInformation& info); 

static bool IsUserModeHideActive( _In_ const ShareDataContainer* shared_sh_data);
  

extern "C" {
	CHAR *PsGetProcessImageFileName(PEPROCESS EProcess);
}
#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, TruthAllocateHiddenData)
#pragma alloc_text(INIT, TruthAllocateSharedDataContainer) 
#pragma alloc_text(PAGE, TruthCreateNewHiddenNode)
#pragma alloc_text(PAGE, TruthFreeHiddenData)
#pragma alloc_text(PAGE, TruthFreeSharedHiddenData)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//
////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
//-------------------------------------------------------------------------------//

_Use_decl_annotations_ static VOID GetPhysicalAddressByNewCR3(
	_In_ PVOID va, 
	_In_ ULONG64 newCR3, 
	_Out_ ULONG64* newPA
)
{
	PHYSICAL_ADDRESS oldPA = { 0 };
	if (newCR3 && va)
	{
		ULONG64 oldCR3 = 0;
		oldCR3 = __readcr3();
		__writecr3(newCR3);
		oldPA = MmGetPhysicalAddress(va);
		if (!oldPA.QuadPart)
		{
			//KeBugCheckEx(0x22334455, oldPA.QuadPart, (ULONG_PTR)va, (ULONG_PTR)newCR3, (ULONG_PTR)oldCR3);
		}
		__writecr3(oldCR3);
	}
	*newPA = oldPA.QuadPart;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ static VOID ModifyEPTEntryRWX(
	_In_ EptData* ept_data, 
	_In_ ULONG64 GuestPhysicalAddress,
	_In_ ULONG64 MachinePhysicalAddres,
	_In_ BOOLEAN ReadAccess,
	_In_ BOOLEAN WriteAccess,
	_In_ BOOLEAN ExecuteAccess
)
{
	auto entry = EptGetEptPtEntry(ept_data, GuestPhysicalAddress);

	entry->fields.read_access	 = ReadAccess;
	entry->fields.execute_access = ExecuteAccess;  
	entry->fields.write_access	 = WriteAccess;
	entry->fields.physial_address = UtilPfnFromPa(MachinePhysicalAddres); 
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C HiddenData* TruthAllocateHiddenData() {
  PAGED_CODE();

  auto p = new HiddenData();
  RtlFillMemory(p, sizeof(HiddenData), 0);
  return p;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C void TruthFreeHiddenData(
    HiddenData* sh_data) {
  PAGED_CODE();
  delete sh_data;
}
//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C ShareDataContainer* TruthAllocateSharedDataContainer() {
  PAGED_CODE();
  auto p = new ShareDataContainer();
  RtlFillMemory(p, sizeof(ShareDataContainer), 0);
  return p;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C void TruthFreeSharedHiddenData(
    ShareDataContainer* shared_sh_data
) 
{
  PAGED_CODE();
  delete shared_sh_data;
}


//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C NTSTATUS TruthStartHiddenEngine()
{
	PAGED_CODE();
	//VM-CALL, after vm-call trap into VMM
	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kEnableAllHideMemory, nullptr);
	},
		nullptr);
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C NTSTATUS TruthStopHiddenEngine() {
	PAGED_CODE();

	NTSTATUS status; 
	status = UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kDisableAllHideMemory, nullptr);
	},
		nullptr);

	if (NT_SUCCESS(status))
	{
		status = UtilVmCall(HypercallNumber::kRemoveAllHideNode, nullptr);
	}
	return status;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C NTSTATUS TruthDisableHideByProcess(PEPROCESS proc)
{
	PAGED_CODE();

	NTSTATUS status; 
	status = UtilForEachProcessor(
		[](void* context) {
		return UtilVmCall(HypercallNumber::kDisableSingleHideMemory, context);
	},
		proc);

	if (NT_SUCCESS(status))
	{
		status = UtilVmCall(HypercallNumber::kRemoveSingleHideNode, proc);
	}
	return status;
} 

//--------------------------------------------------------------------------//
_Use_decl_annotations_ void TruthEnableAllMemoryHide(
	HiddenData *data,	
	EptData* ept_data, 
	ShareDataContainer* shared_sh_data
)
{
	KeInitializeSpinLock(&shared_sh_data->SpinLock);
	for (auto& info : shared_sh_data->UserModeList)
	{  
		TruthEnableEntryForExecuteOnly(*info, ept_data);
	} 
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ void TruthDisableAllMemoryHide(
	_In_ EptData* ept_data, 
	_In_ ShareDataContainer* shared_sh_data
)
{
	for (auto& info : shared_sh_data->UserModeList) 
	{
		TruthDisableVarHiding(*info, ept_data);
	}
}
 
//------------------------------------------------------------------------//
_Use_decl_annotations_ void TruthDisableSingleMemoryHide(
	_In_ EptData* ept_data, 
	_In_ ShareDataContainer* shared_sh_data,
	_In_ PEPROCESS proc
) 
{  
	for (auto& info : shared_sh_data->UserModeList)
	{
		if (info->proc == proc)
		{
			//info
			TruthDisableVarHiding(*info, ept_data);
 			break;
		}
	}
}

//--------------------------------------------------------------------------//
_Use_decl_annotations_ void TruthRemoveAllHideNode(
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data
)
{
	HYPERPLATFORM_LOG_ERROR("All - ListSize: %d", shared_sh_data->UserModeList.size());

	for (auto& info : shared_sh_data->UserModeList)
	{ 
			shared_sh_data->UserModeList.erase(
				std::remove(
					shared_sh_data->UserModeList.begin(),
					shared_sh_data->UserModeList.end(),
					info
				),
				shared_sh_data->UserModeList.end()
			); 
	} 

	HYPERPLATFORM_LOG_ERROR("All - ListSize: %d", shared_sh_data->UserModeList.size());
}

//--------------------------------------------------------------------------//
_Use_decl_annotations_ void TruthRemoveSingleHideNode(
	_In_ EptData* ept_data,
	_In_ ShareDataContainer* shared_sh_data,
	_In_ PEPROCESS proc
)
{
	HYPERPLATFORM_LOG_ERROR("Single - ListSize: %d", shared_sh_data->UserModeList.size());

	for (auto& info : shared_sh_data->UserModeList)
	{
		if (info->proc == proc)
		{  
			shared_sh_data->UserModeList.erase(
				std::remove(
					shared_sh_data->UserModeList.begin(),
					shared_sh_data->UserModeList.end(),
					info
				),
				shared_sh_data->UserModeList.end()
			);
 			break; 
		}
	} 			

	HYPERPLATFORM_LOG_ERROR("Single - ListSize: %d", shared_sh_data->UserModeList.size());
}
//------------------------------------------------------------------------//
_Use_decl_annotations_ bool TruthHandleBreakpoint(
	HiddenData* sh_data,
	const ShareDataContainer* shared_sh_data,
	void* guest_ip) 
{
  UNREFERENCED_PARAMETER(sh_data);
  return true;
}
//------------------------------------------------------------------------//
// Handles MTF VM-exit. Re-enables the shadow hook and clears MTF.
_Use_decl_annotations_ void TruthHandleMonitorTrapFlag(
    HiddenData* sh_data, 
	ShareDataContainer* shared_sh_data,
    EptData* ept_data) 
{	
	NT_VERIFY(IsUserModeHideActive(shared_sh_data));

	KeAcquireInStackQueuedSpinLockAtDpcLevel(&shared_sh_data->SpinLock, &shared_sh_data->LockHandle);
	 
	const auto info = TruthRestoreLastHideInfo(sh_data);         //get back last written EPT-Pte
	TruthEnableEntryForExecuteOnly(*info, ept_data);		     //turn back read-only	  
	TruthSetMonitorTrapFlag(sh_data, false);

	KeReleaseSpinLockFromDpcLevel(&shared_sh_data->SpinLock);

} 

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ bool TruthHandleEptViolation(
	HiddenData* sh_data,  
	ShareDataContainer* shared_sh_data,
	EptData* ept_data, 
	void* fault_va, 
	void* fault_pa ,
	bool IsExecute, 
	bool IsWrite , 
	bool IsRead
)
{ 
	 KeAcquireInStackQueuedSpinLockAtDpcLevel(
		&shared_sh_data->SpinLock, 
		&shared_sh_data->LockHandle
	); 

	if (!IsUserModeHideActive(shared_sh_data)) 
	{
		return false;
	}

	//This have to handle carefully. Easily got hang from this. If we can't find 
	const auto info = TruthFindHideInfoByPhyAddr(shared_sh_data,  (ULONG64)fault_pa);

	if (!info) {
		HYPERPLATFORM_LOG_DEBUG("Cannot find info %d  fault_pa: %I64X  \r\n" ,PsGetCurrentProcessId(), fault_pa);
		return false;
	}

	//Read in single page
	if (IsRead)
	{
		TruthEnableEntryForReadOnly(*info, ept_data);
		//Set MTF flags 
		TruthSetMonitorTrapFlag(sh_data, true);
		//used for reset read-only
		TruthSaveLastHideInfo(sh_data, *info);
	}

	//Write,Execute in same page
	if (IsWrite)
	{		
		//Set R/W/!X for RING3/ RING0
		TruthEnableEntryForAll(*info, ept_data);
		//Set MTF flags 
		TruthSetMonitorTrapFlag(sh_data, true);
		//used for reset read-only
		TruthSaveLastHideInfo(sh_data, *info);

	}
	 
	KeReleaseSpinLockFromDpcLevel(&shared_sh_data->SpinLock);
	//after return to Guset OS, run a single instruction --> and trap into VMM again
 return true;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C PMDLX TruthGetHideMDL(
	_In_ ShareDataContainer* shared_sh_data,  
	_In_ PEPROCESS proc
)
{
	for (auto &info : shared_sh_data->UserModeList) 
	{
		if (info->proc == proc)
		{
			return (PMDLX)info->MDL;
		}
	}
	return NULL;
} 

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C bool TruthCreateNewHiddenNode(
	ShareDataContainer* shared_sh_data,
	void* address, 
	const char* name, 
	ULONG64 P_Paddr,
	ULONG64 CR3,//old physical address ,
	PVOID64 mdl,
	PEPROCESS proc
)
{
	VariableHiding Factory;

	if (!shared_sh_data)
	{
		return FALSE;
	} 

	auto info = Factory.CreateNoTruthNode(address, name, CR3, mdl, proc, P_Paddr); 
	shared_sh_data->UserModeList.push_back(std::move(info));

	if (!info)
	{
		return false;
	}	
	HYPERPLATFORM_LOG_INFO("Info Empty Create Failed \r\n");
	return true;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ static HideInformation* TruthFindHideInfoByPhyAddr(
	const ShareDataContainer* shared_sh_data, 
	ULONG64 fault_pa
)
{
	const auto found = std::find_if(shared_sh_data->UserModeList.cbegin(), shared_sh_data->UserModeList.cend(), [fault_pa](const auto& info) {	
		return PAGE_ALIGN(info->NewPhysicalAddress) == PAGE_ALIGN(fault_pa);
	});
	if (found == shared_sh_data->UserModeList.cend()) 
	{
		return nullptr;
	}
	return found->get();
}

//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void TruthEnableEntryForExecuteOnly(const HideInformation& info, EptData* ept_data)
{
	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_exec, FALSE, FALSE, TRUE);
	UtilInveptAll(); 
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void TruthEnableEntryForAll(const HideInformation& info, EptData* ept_data)
{
	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_exec, TRUE, TRUE, TRUE);
	UtilInveptAll();
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void TruthEnableEntryForReadOnly(const HideInformation& info, EptData* ept_data)
{

	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_rw, TRUE, FALSE, FALSE);
	UtilInveptAll();
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void TruthDisableVarHiding(const HideInformation& info, EptData* ept_data)
{
	// ring-3 start 
	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_original_page, TRUE, TRUE, TRUE);  
	UtilInveptAll();
}
// Set MTF on the current processor
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void TruthSetMonitorTrapFlag(HiddenData* sh_data, bool enable)
{
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}


//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void TruthSaveLastHideInfo(HiddenData* sh_data, const HideInformation& info)
{
	KLOCK_QUEUE_HANDLE lock_handle = {};
	NT_ASSERT(!sh_data->UserModeBackup);	
 	sh_data->UserModeBackup = &info; 
}

//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static const HideInformation* TruthRestoreLastHideInfo(
	_In_ HiddenData* sh_data
) 
{
	KLOCK_QUEUE_HANDLE lock_handle = {};
	const auto info = sh_data->UserModeBackup;
	sh_data->UserModeBackup = nullptr;
	return info;
}


//----------------------------------------------------------------------------------------------------------------------
// Checks if NoTruth is already initialized
_Use_decl_annotations_ static bool IsUserModeHideActive(
	_In_ const ShareDataContainer* ShareDataContainer
)
{
  return !!(ShareDataContainer);
}
//----------------------------------------------------------------------------------------------------------------------
// Allocates a non-paged, page-alined page. Issues bug check on failure
Page::Page()
    : page(reinterpret_cast<UCHAR*>(ExAllocatePoolWithTag(
          NonPagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag))) 
{
  if (!page)
  {
    HYPERPLATFORM_COMMON_BUG_CHECK(
        HyperPlatformBugCheck::kCritialPoolAllocationFailure, 0, 0, 0);
  }
}
//----------------------------------------------------------------------------------------------------------------------
// De-allocates the allocated page
Page::~Page() { ExFreePoolWithTag(page, kHyperPlatformCommonPoolTag); }

//----------------------------------------------------------------------------------------------------------------------