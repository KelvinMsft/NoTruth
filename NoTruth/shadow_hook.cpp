// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements shadow hook functions.

#include "shadow_hook.h"
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
struct ShadowHookData {
  const HookInformation* KernelModeBackup;  // Remember which hook hit the last
  const HideInformation* UserModeBackup;   // remember which var hit the last
  ULONG64 PageFault_Phy;
  ULONG64 PageFault_Virt;
  bool IsKernelMemory; 
}; 

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static HideInformation* ShpFindHideInfoByProc(
	const ShareDataContainer* shared_sh_data, ULONG64 fault_pa);

static HideInformation* ShpFindHideInfoByPage(
	const ShareDataContainer* shared_sh_data, void* address);

static HideInformation* ShpFindHideByAddress(
	_In_ const ShareDataContainer* shared_sh_data, _In_ void* address);

//Come from Reading, independent page
static void kEnableEntryForExecuteOnly(_In_ const HideInformation& info, _In_ EptData* ept_data);

//Come from Reading, independent page
static void kEnableEntryForReadOnly(_In_ const HideInformation& info, _In_ EptData* ept_data);

//Come from Write,  reset page for exec. and shared page with exec.
static void kEnableEntryForAll(_In_ const HideInformation& info , _In_ EptData* ept_data);

//Come from execute, reset page for exec. and shared page with write.
//static void K_EnableVarHidingForExec(_In_ const HideInformation& info, _In_ EptData* ept_data);

// After MTF used to reset a page for read-only ( because at most of case, 
// After write AND others read it which is unexpected case 
// As a result, we always have to set it to read-only, 
// so that we can confirm that CPU always used safe-page even after specific write / execute 
static const HideInformation* kRestoreLastHideInfo(_In_ ShadowHookData* sh_data);

static void kDisableVarHiding(_In_ const HideInformation& info,
								_In_ EptData* ept_data);

static void ShpSetMonitorTrapFlag(_In_ ShadowHookData* sh_data,
                                  _In_ bool enable);

static void kSaveLastHideInfo(_In_ ShadowHookData* sh_data,
								_In_ const HideInformation& info);

static const HookInformation* ShpRestoreLastHookInfo(_In_ ShadowHookData* sh_data);

static bool IsUserModeHideActive( _In_ const ShareDataContainer* shared_sh_data);


static ULONG64 RefreshPageTable64(_In_ ULONG64 newCR3);

static VOID GetPhysicalAddressByNewCR3(_In_ ULONG64 va, _In_ ULONG64 newCR3, _Out_ ULONG64* newPA);

static ULONG64 ModifyEPTEntry(_In_ LARGE_INTEGER pa, BOOLEAN read, BOOLEAN write , BOOLEAN exec);

extern "C" {
	CHAR *PsGetProcessImageFileName(PEPROCESS EProcess);
}
#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, ShAllocateShadowHookData)
#pragma alloc_text(INIT, ShAllocateSharedShaowHookData)
#pragma alloc_text(PAGE, ShInstallHide)
#pragma alloc_text(PAGE, kInitHiddenEngine)
#pragma alloc_text(PAGE, ShFreeShadowHookData)
#pragma alloc_text(PAGE, ShFreeSharedShadowHookData)
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
_Use_decl_annotations_ static ULONG64 RefreshPageTable64(
	_In_ ULONG64 newCR3
)
{

}
//-------------------------------------------------------------------------------//
_Use_decl_annotations_ static VOID ModifyEPTEntryRWX(
	EptData* ept_data, 
	ULONG64 Pa, 
	ULONG64 newPa, 
	BOOLEAN read, 
	BOOLEAN write, 
	BOOLEAN exec
)
{
	auto entry = EptGetEptPtEntry(ept_data, Pa);
	entry->fields.execute_access = exec;
	entry->fields.write_access = write;
	entry->fields.read_access = read;
	entry->fields.physial_address = UtilPfnFromPa(newPa);

}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C ShadowHookData* ShAllocateShadowHookData() {
  PAGED_CODE();

  auto p = new ShadowHookData();
  RtlFillMemory(p, sizeof(ShadowHookData), 0);
  return p;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C void ShFreeShadowHookData(
    ShadowHookData* sh_data) {
  PAGED_CODE();

  delete sh_data;
}
//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C ShareDataContainer* ShAllocateSharedShaowHookData() {
  PAGED_CODE();

  auto p = new ShareDataContainer();
  RtlFillMemory(p, sizeof(ShareDataContainer), 0);
  return p;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C void ShFreeSharedShadowHookData(
    ShareDataContainer* shared_sh_data) {
  PAGED_CODE();

  delete shared_sh_data;
}

_Use_decl_annotations_ EXTERN_C NTSTATUS kStartHiddenEngine() {
	PAGED_CODE();
	//VM-CALL, after vm-call trap into VMM
	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kShEnableVarHiding, nullptr);
	},
		nullptr);
}
_Use_decl_annotations_ EXTERN_C NTSTATUS kStopHiddenEngine() {
	PAGED_CODE();
	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kShdisableVarHiding, nullptr);
	},
		nullptr);
}
_Use_decl_annotations_ EXTERN_C NTSTATUS kDisableHideByProcess(PEPROCESS proc) {
	PAGED_CODE();
	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kIndependentHiding, nullptr);
		},
		nullptr);
}
//--------------------------------------------------------------------------//
_Use_decl_annotations_ NTSTATUS kEnableVarHiding(
	ShadowHookData *data,	
	EptData* ept_data, 
	 ShareDataContainer* shared_sh_data
)
{
	KeInitializeSpinLock(&shared_sh_data->SpinLock);
	for (auto& info : shared_sh_data->UserModeList)
	{ 
		HYPERPLATFORM_LOG_DEBUG("[START]VMM enable var hide CR3: %lu \r\n", info->CR3);
		kEnableEntryForExecuteOnly(*info, ept_data); 
	}
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ void kVmCallDisableVarHiding(_In_ EptData* ept_data, _In_ ShareDataContainer* shared_sh_data) 
{
	for (auto& info : shared_sh_data->UserModeList) 
	{
		kDisableVarHiding(*info, ept_data);
	}
}

//use with other SetTerminateProcess
//------------------------------------------------------------------------//
_Use_decl_annotations_ void kVmCallDisableVarHidingIndependently(_In_ EptData* ept_data, _In_ ShareDataContainer* shared_sh_data) 
{
	ULONG count = 0;
	for (auto& info : shared_sh_data->UserModeList)
	{
		if (info->isExit == TRUE && info->isDelete == FALSE)
		{
			kDisableVarHiding(*info, ept_data);
			count++; 
			info->isDelete = TRUE;
			break;
		}
	}
}

//------------------------------------------------------------------------//
_Use_decl_annotations_ bool ShHandleBreakpoint(
	ShadowHookData* sh_data,
	const ShareDataContainer* shared_sh_data,
	void* guest_ip) 
{
  UNREFERENCED_PARAMETER(sh_data);
  return true;
}
//------------------------------------------------------------------------//
// Handles MTF VM-exit. Re-enables the shadow hook and clears MTF.
_Use_decl_annotations_ void ShHandleMonitorTrapFlag(
    ShadowHookData* sh_data, 
	ShareDataContainer* shared_sh_data,
    EptData* ept_data) 
{	
	NT_VERIFY(IsUserModeHideActive(shared_sh_data));

	KeAcquireInStackQueuedSpinLockAtDpcLevel(&shared_sh_data->SpinLock, &shared_sh_data->LockHandle);

	if(!sh_data->IsKernelMemory)
	{
		const auto info = kRestoreLastHideInfo(sh_data);         //get back last written EPT-Pte
		kEnableEntryForExecuteOnly(*info, ept_data);		     //turn back read-only	 
	}

	ShpSetMonitorTrapFlag(sh_data, false);

	KeReleaseSpinLockFromDpcLevel(&shared_sh_data->SpinLock);

} 

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ bool kHandleEptViolation(
	ShadowHookData* sh_data,  
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
	//const auto info = ShpFindHideInfoByPage(shared_sh_data, fault_va);
	const auto info = ShpFindHideInfoByProc(shared_sh_data,  (ULONG64)fault_pa);

	if (!info) {
		HYPERPLATFORM_LOG_DEBUG("Cannot find info %d \r\n" ,PsGetCurrentProcessId());
		return false;
	}

	//Read in single page
	if (IsRead)
	{
		kEnableEntryForReadOnly(*info, ept_data);
		//Set MTF flags 
		ShpSetMonitorTrapFlag(sh_data, true);
		//used for reset read-only
		kSaveLastHideInfo(sh_data, *info);
	}

	//Write,Execute in same page
	if (IsWrite)
	{		
		//Set R/W/!X for RING3/ RING0
		kEnableEntryForAll(*info, ept_data);
		//Set MTF flags 
		ShpSetMonitorTrapFlag(sh_data, true);
		//used for reset read-only
		kSaveLastHideInfo(sh_data, *info);

	}
	 
	KeReleaseSpinLockFromDpcLevel(&shared_sh_data->SpinLock);
	//after return to Guset OS, run a single instruction --> and trap into VMM again
 return true;
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C PMDLX GetHideMDL(
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
_Use_decl_annotations_ EXTERN_C VOID SetTerminateProcess(
	_In_ ShareDataContainer* shared_sh_data, 
	_In_ PEPROCESS proc
)
{
	for (auto &info : shared_sh_data->UserModeList)
	{
		if (info->proc == proc)
		{
			info->isExit = TRUE;
		}
	}
}

//-------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C bool kInitHiddenEngine(
	ShareDataContainer* shared_sh_data,
	void* address,
	ShadowHookTarget* target,
	const char* name,
	bool isVar,
	bool isRing3,
	ULONG64 P_Paddr,
	ULONG64 CR3,//old physical address ,
	PVOID64 mdl,
	PEPROCESS proc
)
{
	VariableHiding V;
	auto info = V.CreateHidingInformation(address, name, CR3, mdl, proc, isRing3, P_Paddr);
	HYPERPLATFORM_LOG_DEBUG("info->proc : %I64x P_Paddr : 0x%I64X", info->proc, P_Paddr);
	shared_sh_data->UserModeList.push_back(std::move(info));
	return TRUE;
}
//-------------------------------------------------------------------------------//
_Use_decl_annotations_ static HideInformation* ShpFindHideInfoByProc(
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
//---------------------------------------------------------------------------------------------//
_Use_decl_annotations_ static HideInformation* ShpFindHideInfoByPage(
	const ShareDataContainer* shared_sh_data, 
	void* address
)
{
	const auto found = std::find_if(shared_sh_data->UserModeList.cbegin(), shared_sh_data->UserModeList.cend(), [address](const auto& info) {
		return PAGE_ALIGN(info->patch_address) == PAGE_ALIGN(address);
	});
	if (found == shared_sh_data->UserModeList.cend()) {
		return nullptr;
	}

	return found->get();
}

//------------------------------------------------------------------------------------------//
static HideInformation* ShpFindHideByAddress(
	_In_ const ShareDataContainer* shared_sh_data,
	_In_ void* address)
{
	auto found = std::find_if
	(
		shared_sh_data->UserModeList.cbegin(), shared_sh_data->UserModeList.cend(),
		[address](const auto& info) 
		{ 
			return info->patch_address == address; 
		}
	);

	if (found == shared_sh_data->UserModeList.cend()) 
	{
		return nullptr;
	}
	return found->get();
}

//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void kEnableEntryForExecuteOnly(const HideInformation& info, EptData* ept_data) 
{
	if (info.isRing3) 
	{
		ULONG64 newPA = 0;
		GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
		ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_exec, FALSE, FALSE, TRUE);
	}
	//re-set EPT TLB
	UtilInveptAll(); 
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void kEnableEntryForAll(const HideInformation& info, EptData* ept_data)
{
	if (info.isRing3) 
	{ 	
		ULONG64 newPA = 0;
		GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
		ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_exec, TRUE, TRUE, TRUE);
	}
	UtilInveptAll();
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void kEnableEntryForReadOnly(const HideInformation& info, EptData* ept_data)
{
	if (info.isRing3)
	{
		// ring-3 start 
		ULONG64 newPA = 0;
		GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
		ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_rw, TRUE, FALSE, FALSE);
		// ring-3 end
	}
	UtilInveptAll();
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void kDisableVarHiding(const HideInformation& info, EptData* ept_data)
{
	// ring-3 start 
	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_rw, TRUE, TRUE, TRUE);
	UtilInveptAll();
}
// Set MTF on the current processor
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void ShpSetMonitorTrapFlag(ShadowHookData* sh_data, bool enable) 
{
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}


//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static void kSaveLastHideInfo(ShadowHookData* sh_data, const HideInformation& info) 
{
	KLOCK_QUEUE_HANDLE lock_handle = {};
	NT_ASSERT(!sh_data->UserModeBackup);	
 	sh_data->UserModeBackup = &info;
	sh_data->IsKernelMemory = FALSE;
}

//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static const HideInformation* kRestoreLastHideInfo(ShadowHookData* sh_data) 
{
	KLOCK_QUEUE_HANDLE lock_handle = {};
	const auto info = sh_data->UserModeBackup;
	sh_data->UserModeBackup = nullptr;
	return info;
}
//----------------------------------------------------------------------------------------------------------------------
_Use_decl_annotations_ static const HookInformation* ShpRestoreLastHookInfo(ShadowHookData* sh_data) 
{
	  NT_ASSERT(sh_data->KernelModeBackup);
	  auto info = sh_data->KernelModeBackup;
	  sh_data->KernelModeBackup = nullptr;
	  return info;
}

// Checks if NoTruth is already initialized
_Use_decl_annotations_ static bool IsUserModeHideActive(const ShareDataContainer* ShareDataContainer) 
{
  return !!(ShareDataContainer);
}

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

// De-allocates the allocated page
Page::~Page() { ExFreePoolWithTag(page, kHyperPlatformCommonPoolTag); }