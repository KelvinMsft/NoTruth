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
struct SharedShadowHookData {
  std::vector<std::unique_ptr<HideInformation>> UserModeList; //var hide
};

// Data structure for each processor
struct ShadowHookData {
  const HookInformation* KernelModeBackup;  // Remember which hook hit the last
  const HideInformation* UserModeBackup;   // remember which var hit the last
  ULONG64 PageFault_Phy;
  ULONG64 PageFault_Virt;
  bool IsKernelMemory; 
  KSPIN_LOCK spin_lock;
};

// A structure reflects inline hook code.
#include <pshpack1.h>
#if defined(_AMD64_)

struct TrampolineCode {
  UCHAR nop;
  UCHAR jmp[6];
  void* address;
};
static_assert(sizeof(TrampolineCode) == 15, "Size check");

#else

struct TrampolineCode {
  UCHAR nop;
  UCHAR push;
  void* address;
  UCHAR ret;
};
static_assert(sizeof(TrampolineCode) == 7, "Size check");

#endif
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static HideInformation* ShpFindHideInfoByProc(
	const SharedShadowHookData* shared_sh_data, ULONG64 fault_pa);

static HideInformation* ShpFindHideInfoByPage(
	const SharedShadowHookData* shared_sh_data, void* address);

static HideInformation* ShpFindHideByAddress(
	_In_ const SharedShadowHookData* shared_sh_data, _In_ void* address);

//Come from Reading, independent page
static void kEnableEntryForExecuteOnly(_In_ const HideInformation& info, _In_ EptData* ept_data);

//Come from Reading, independent page
static void kEnableEntryForReadAndExecuteOnly(_In_ const HideInformation& info, _In_ EptData* ept_data);

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

static void ShpSaveLastHookInfo(_In_ ShadowHookData* sh_data,
                                _In_ const HookInformation& info);

static void kSaveLastHideInfo(_In_ ShadowHookData* sh_data,
								_In_ const HideInformation& info);

static const HookInformation* ShpRestoreLastHookInfo(_In_ ShadowHookData* sh_data);

static bool ShpIsShadowHookActive( _In_ const SharedShadowHookData* shared_sh_data);


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
_Use_decl_annotations_ static VOID GetPhysicalAddressByNewCR3(_In_ PVOID va, _In_ ULONG64 newCR3, _Out_ ULONG64* newPA)
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
_Use_decl_annotations_ static ULONG64 RefreshPageTable64(_In_ ULONG64 newCR3)
{

}

_Use_decl_annotations_ static VOID ModifyEPTEntryRWX(EptData* ept_data, ULONG64 Pa, ULONG64 newPa, BOOLEAN read, BOOLEAN write, BOOLEAN exec)
{
	auto entry = EptGetEptPtEntry(ept_data, Pa);
	entry->fields.execute_access = exec;
	entry->fields.write_access = write;
	entry->fields.read_access = read;
	entry->fields.physial_address = UtilPfnFromPa(newPa);

}



_Use_decl_annotations_ EXTERN_C ShadowHookData* ShAllocateShadowHookData() {
  PAGED_CODE();

  auto p = new ShadowHookData();
  RtlFillMemory(p, sizeof(ShadowHookData), 0);
  return p;
}

// Terminates NoTruth
_Use_decl_annotations_ EXTERN_C void ShFreeShadowHookData(
    ShadowHookData* sh_data) {
  PAGED_CODE();

  delete sh_data;
}

// Initializes NoTruth
_Use_decl_annotations_ EXTERN_C SharedShadowHookData* ShAllocateSharedShaowHookData() {
  PAGED_CODE();

  auto p = new SharedShadowHookData();
  RtlFillMemory(p, sizeof(SharedShadowHookData), 0);
  return p;
}

//
_Use_decl_annotations_ EXTERN_C void ShFreeSharedShadowHookData(
    SharedShadowHookData* shared_sh_data) {
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
	const SharedShadowHookData* shared_sh_data
)
{
	KeInitializeSpinLock(&data->spin_lock);
	for (auto& info : shared_sh_data->UserModeList)
	{ 
		HYPERPLATFORM_LOG_DEBUG("[START]VMM enable var hide CR3: %lu \r\n", info->CR3);
		kEnableEntryForExecuteOnly(*info, ept_data); 
	}
	return STATUS_SUCCESS;
}


_Use_decl_annotations_ void kVmCallDisableVarHiding(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data) 
{
	for (auto& info : shared_sh_data->UserModeList) 
	{
		kDisableVarHiding(*info, ept_data);
	}
}

//use with other SetTerminateProcess
//------------------------------------------------------------------------//
_Use_decl_annotations_ void kVmCallDisableVarHidingIndependently(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data) 
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

// Handles #BP. Checks if the #BP happened on where NoTruth set a break point,
// and if so, modifies the contents of guest's IP to execute a corresponding
// hook handler.

//------------------------------------------------------------------------//
_Use_decl_annotations_ bool ShHandleBreakpoint(
	ShadowHookData* sh_data,
	const SharedShadowHookData* shared_sh_data,
	void* guest_ip) 
{
  UNREFERENCED_PARAMETER(sh_data);
  return true;
}
//------------------------------------------------------------------------//
// Handles MTF VM-exit. Re-enables the shadow hook and clears MTF.
PKAPC_STATE apc;
_Use_decl_annotations_ void ShHandleMonitorTrapFlag(
    ShadowHookData* sh_data, 
	const SharedShadowHookData* shared_sh_data,
    EptData* ept_data) 
{	
	NT_VERIFY(ShpIsShadowHookActive(shared_sh_data));
 
	if(!sh_data->IsKernelMemory)
	{
		const auto info = kRestoreLastHideInfo(sh_data);//get back last written EPT-Pte
		kEnableEntryForExecuteOnly(*info, ept_data);		     //turn back read-only	 
	}

	ShpSetMonitorTrapFlag(sh_data, false);
} 



// Handles EPT violation VM-exit.
// For hidden-variable / data  queue
BOOLEAN isLog;
//
_Use_decl_annotations_ bool kHandleEptViolation(
	ShadowHookData* sh_data, const SharedShadowHookData* shared_sh_data,
	EptData* ept_data, void* fault_va, void* fault_pa ,bool IsExecute, bool IsWrite , bool IsRead) 
{ 

	if (!ShpIsShadowHookActive(shared_sh_data)) 
	{
		return false;
	}
	//find a page in var_hide list
	//const auto info = ShpFindHideInfoByPage(shared_sh_data, fault_va);
	const auto info = ShpFindHideInfoByProc(shared_sh_data,  (ULONG64)fault_pa);

	if (!info) {
		HYPERPLATFORM_LOG_DEBUG("Cannot find info %d \r\n" ,PsGetCurrentProcessId());
		return false;
	}

	if (IsRead)
	{
		kEnableEntryForReadAndExecuteOnly(*info, ept_data);
		//Set MTF flags 
		ShpSetMonitorTrapFlag(sh_data, true);
		//used for reset read-only
		kSaveLastHideInfo(sh_data, *info);
	}
	if (IsWrite)
	{		
		//Set R/W/!X for RING3/ RING0
		kEnableEntryForAll(*info, ept_data);
		//Set MTF flags 
		ShpSetMonitorTrapFlag(sh_data, true);
		//used for reset read-only
		kSaveLastHideInfo(sh_data, *info);
	}
	
	//after return to Guset OS, run a single instruction --> and trap into VMM again
 return true;
}
// Set up inline hook at the address without activating it
//test
_Use_decl_annotations_ EXTERN_C PMDLX GetHideMDL(_In_ SharedShadowHookData* shared_sh_data,  _In_ PEPROCESS proc) 
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
//test
_Use_decl_annotations_ EXTERN_C VOID SetTerminateProcess(_In_ SharedShadowHookData* shared_sh_data, _In_ PEPROCESS proc)
{
	for (auto &info : shared_sh_data->UserModeList)
	{
		if (info->proc == proc)
		{
			info->isExit = TRUE;
		}
	}
}
//test


_Use_decl_annotations_ EXTERN_C bool kInitHiddenEngine(
	SharedShadowHookData* shared_sh_data,
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

_Use_decl_annotations_ static HideInformation* ShpFindHideInfoByProc(const SharedShadowHookData* shared_sh_data, ULONG64 fault_pa)
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
_Use_decl_annotations_ static HideInformation* ShpFindHideInfoByPage(const SharedShadowHookData* shared_sh_data, void* address)
{
	const auto found = std::find_if(shared_sh_data->UserModeList.cbegin(), shared_sh_data->UserModeList.cend(), [address](const auto& info) {
		return PAGE_ALIGN(info->patch_address) == PAGE_ALIGN(address);
	});
	if (found == shared_sh_data->UserModeList.cend()) {
		return nullptr;
	}

	return found->get();
}


static HideInformation* ShpFindHideByAddress(_In_ const SharedShadowHookData* shared_sh_data, _In_ void* address)
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
//  #################################2016.8.4 edited by Kelvin Chan###############################
//	EPT entry Cannot be set execute / write-only , so that the page is always avaiable for read
//	Means we need to restore the page after EIP/RIP , otherwise, someones will read the same page with Write page 
//  We set MTF for do this.
//  Distinct the function between W/X just for clear.  
//  #################################2016.8.4 edited by Kelvin Chan###############################

//Come here from Read memory or Initialization
_Use_decl_annotations_ static void kEnableEntryForExecuteOnly(const HideInformation& info, EptData* ept_data) 
{
	if (info.isRing3) 
	{
	//ring-3 start
		ULONG64 newPA = 0;
		GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
		ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_exec, FALSE, FALSE, TRUE);
	//ring-3 end
	}
	else 
	{
	//ring-0 start 
		const auto ept_pt_entry = EptGetEptPtEntry(ept_data, UtilPaFromVa(info.patch_address));
		ept_pt_entry->fields.write_access = false;
		ept_pt_entry->fields.read_access = true;
		ept_pt_entry->fields.physial_address = UtilPfnFromPa(info.pa_base_for_exec);
		*(PULONG64)((LONG64)info.shadow_page_base_for_exec->page + BYTE_OFFSET(info.patch_address) + 0x1F0) = (ULONG64)0x0;	
	//ring-0 end
	}
	//re-set EPT TLB
	UtilInveptAll(); 
}
//Come here from Write memory, Actaully it is set to Wrtie only, but it will cause EPT misconfiguration exception
_Use_decl_annotations_ static void kEnableEntryForAll(const HideInformation& info, EptData* ept_data)
{
	if (info.isRing3) 
	{ 	
	// ring-3 start 
		ULONG64 newPA = 0;
		GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
		ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_exec, TRUE, TRUE, TRUE);
	// ring-3 end
	}
	UtilInveptAll();
}
//Come here from Execute memory
//if who wants execute the memory --> let it execute
_Use_decl_annotations_ static void kEnableEntryForReadAndExecuteOnly(const HideInformation& info, EptData* ept_data)
{
	if (info.isRing3)
	{
		// ring-3 start 
		ULONG64 newPA = 0;
		GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
		ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_rw, TRUE, FALSE, TRUE);
		// ring-3 end
	}
	UtilInveptAll();
}

_Use_decl_annotations_ static void kDisableVarHiding(const HideInformation& info, EptData* ept_data)
{
	// ring-3 start 
	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_rw, TRUE, TRUE, TRUE);
	UtilInveptAll();
}
// Set MTF on the current processor
// ÷√ÜŒ≤ΩÆê≥£ 
_Use_decl_annotations_ static void ShpSetMonitorTrapFlag(ShadowHookData* sh_data, bool enable) 
{
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}


// Hidden ring0/ring3 any address , isolated write & execute and read
_Use_decl_annotations_ static void kSaveLastHideInfo(ShadowHookData* sh_data, const HideInformation& info) 
{
	KLOCK_QUEUE_HANDLE lock_handle = {};
	KeAcquireInStackQueuedSpinLockAtDpcLevel(&sh_data->spin_lock, &lock_handle);
	NT_ASSERT(!sh_data->UserModeBackup);	
 	sh_data->UserModeBackup = &info;
	sh_data->IsKernelMemory = FALSE;
	KeReleaseInStackQueuedSpinLock(&lock_handle);
}

// Retrieves the last HideInformation after MTF for Ring3/Ring0 variable hiding
_Use_decl_annotations_ static const HideInformation* kRestoreLastHideInfo(ShadowHookData* sh_data) 
{
	KLOCK_QUEUE_HANDLE lock_handle = {};
	KeAcquireInStackQueuedSpinLockAtDpcLevel(&sh_data->spin_lock, &lock_handle);
	NT_ASSERT(sh_data->UserModeBackup);
	const auto info = sh_data->UserModeBackup;
	sh_data->UserModeBackup = nullptr;
	KeReleaseInStackQueuedSpinLock(&lock_handle);
	return info;
}
// Retrieves the last HookInformation after MTF for ring0 hooking hiding
_Use_decl_annotations_ static const HookInformation* ShpRestoreLastHookInfo(ShadowHookData* sh_data) 
{
	  NT_ASSERT(sh_data->KernelModeBackup);
	  auto info = sh_data->KernelModeBackup;
	  sh_data->KernelModeBackup = nullptr;
	  return info;
}
// Saves HookInformation as the last one for reusing it on up coming MTF VM-exit
// Hidden ring0 Hook
_Use_decl_annotations_ static void ShpSaveLastHookInfo(ShadowHookData* sh_data, const HookInformation& info) 
{
	NT_ASSERT(!sh_data->KernelModeBackup);
	sh_data->KernelModeBackup = &info;
	sh_data->IsKernelMemory = TRUE;
}
// Checks if NoTruth is already initialized
_Use_decl_annotations_ static bool ShpIsShadowHookActive(const SharedShadowHookData* shared_sh_data) 
{
  return !!(shared_sh_data);
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