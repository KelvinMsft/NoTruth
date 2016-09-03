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
#include "cs_driver_mm.h"
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

// Contains a single steal thook information

struct HookInformation {
  void* patch_address;  // An address where a hook is installed
  void* handler;        // An address of the handler routine

  // A copy of a pages where patch_address belongs to. shadow_page_base_for_rw
  // is exposed to a guest for read and write operation against the page of
  // patch_address, and shadow_page_base_for_exec is exposed for execution.
  std::shared_ptr<Page> shadow_page_base_for_rw;	//VA for rw hooking page of created / retrieved page of Original page
  std::shared_ptr<Page> shadow_page_base_for_exec;  //VA for exec hooking page of created / retrieved page of Original page

  // Phyisical address of the above two copied pages
  ULONG64 pa_base_for_rw;							//PA of above
  ULONG64 pa_base_for_exec;							//PA of above

  // A name of breakpont (a DDI name)
  std::array<char, 64> name;
};


// Data structure shared across all processors
struct SharedShadowHookData {
  std::vector<std::unique_ptr<HookInformation>> KernelModeList;  // Hold installed KernelModeList
  std::vector<std::unique_ptr<HideInformation>> UserModeList; //var hide
};

// Data structure for each processor
struct ShadowHookData {
  const HookInformation* KernelModeBackup;  // Remember which hook hit the last
  const HideInformation* UserModeBackup;   // remember which var hit the last
  ULONG64 PageFault_Phy;
  ULONG64 PageFault_Virt;
  bool IsKernelMemory;
  bool CopyOnWrite;
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

_IRQL_requires_max_(PASSIVE_LEVEL) static std::
    unique_ptr<HookInformation> ShpCreateHookInformation(
        _In_ SharedShadowHookData* shared_sh_data, _In_ void* address,
        _In_ ShadowHookTarget* target, _In_ const char* name);

_IRQL_requires_max_(PASSIVE_LEVEL) _Success_(return ) EXTERN_C
    static bool ShpSetupInlineHook(_In_ void* patch_address,
                                   _In_ UCHAR* shadow_exec_page,
                                   _Out_ void** original_call_ptr);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static SIZE_T
    ShpGetInstructionSize(_In_ void* address);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static TrampolineCode
    ShpMakeTrampolineCode(_In_ void* hook_handler);

static HookInformation* ShpFindPatchInfoByPage(
    _In_ const SharedShadowHookData* shared_sh_data, _In_ void* address);


static HideInformation* ShpFindHideInfoByProc(
	const SharedShadowHookData* shared_sh_data, void* Proc);

static HideInformation* ShpFindHideInfoByPage(
	const SharedShadowHookData* shared_sh_data, void* address);

static HideInformation* ShpFindHideByAddress(
	_In_ const SharedShadowHookData* shared_sh_data, _In_ void* address);

static HookInformation* ShpFindPatchInfoByAddress(
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


static void ShpEnablePageShadowingForExec(_In_ const HookInformation& info,
                                          _In_ EptData* ept_data);

static void ShpEnablePageShadowingForRW(_In_ const HookInformation& info,
                                        _In_ EptData* ept_data);

static void ShpDisablePageShadowing(_In_ const HookInformation& info,
                                    _In_ EptData* ept_data);

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
#pragma alloc_text(INIT, ShEnableHooks)
#pragma alloc_text(PAGE, ShInstallHide)
#pragma alloc_text(PAGE, kInitHiddenEngine)
#pragma alloc_text(INIT, ShpSetupInlineHook)
#pragma alloc_text(INIT, ShpGetInstructionSize)
#pragma alloc_text(INIT, ShpMakeTrampolineCode)
#pragma alloc_text(PAGE, ShFreeShadowHookData)
#pragma alloc_text(PAGE, ShFreeSharedShadowHookData)
#pragma alloc_text(PAGE, ShDisableHooks)
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

// Terminates DdiMon
_Use_decl_annotations_ EXTERN_C void ShFreeShadowHookData(
    ShadowHookData* sh_data) {
  PAGED_CODE();

  delete sh_data;
}

// Initializes DdiMon
_Use_decl_annotations_ EXTERN_C SharedShadowHookData* ShAllocateSharedShaowHookData() {
  PAGED_CODE();

  if (cs_driver_mm_init() != CS_ERR_OK) {
    return nullptr;
  }

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

// Enables page shadowing for all KernelModeList
_Use_decl_annotations_ EXTERN_C NTSTATUS ShEnableHooks() {
  PAGED_CODE();
  return UtilForEachProcessor(
      [](void* context) {
        UNREFERENCED_PARAMETER(context);
        return UtilVmCall(HypercallNumber::kShEnablePageShadowing, nullptr);
      },
      nullptr);
}

// Disables page shadowing for all KernelModeList
_Use_decl_annotations_ EXTERN_C NTSTATUS ShDisableHooks() {
  PAGED_CODE();

  return UtilForEachProcessor(
      [](void* context) {
        UNREFERENCED_PARAMETER(context);
        return UtilVmCall(HypercallNumber::kShDisablePageShadowing, nullptr);
      },
      nullptr);
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

_Use_decl_annotations_ NTSTATUS kEnableVarHiding(ShadowHookData *data,	EptData* ept_data, const SharedShadowHookData* shared_sh_data) {
	KeInitializeSpinLock(&data->spin_lock);
	data->CopyOnWrite = FALSE;
	for (auto& info : shared_sh_data->UserModeList)
	{
		//是否已經被隱藏
		if (!info->isHidden) 
		{
			HYPERPLATFORM_LOG_DEBUG("[START]VMM enable var hide CR3: %lu \r\n", info->CR3);
			kEnableEntryForExecuteOnly(*info, ept_data);
			info->isHidden = TRUE;
		}
	}
	return STATUS_SUCCESS;
}

// Enables page shadowing for all KernelModeList
_Use_decl_annotations_ NTSTATUS ShEnablePageShadowing(
    EptData* ept_data, const SharedShadowHookData* shared_sh_data) {
 // HYPERPLATFORM_COMMON_DBG_BREAK();

  for (auto& info : shared_sh_data->KernelModeList) {
    ShpEnablePageShadowingForExec(*info, ept_data);
  }

  return STATUS_SUCCESS;
}	

// Disables page shadowing for all KernelModeList
_Use_decl_annotations_ void ShVmCallDisablePageShadowing(EptData* ept_data, const SharedShadowHookData* shared_sh_data) 
{
  for (auto& info : shared_sh_data->KernelModeList) 
  {
    ShpDisablePageShadowing(*info, ept_data);
  }
}

_Use_decl_annotations_ void kVmCallDisableVarHiding(_In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data) 
{
	for (auto& info : shared_sh_data->UserModeList) 
	{
		kDisableVarHiding(*info, ept_data);
	}
}

//use with other SetTerminateProcess
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

// Handles #BP. Checks if the #BP happened on where DdiMon set a break point,
// and if so, modifies the contents of guest's IP to execute a corresponding
// hook handler.

//?理#bp異常
_Use_decl_annotations_ bool ShHandleBreakpoint(
	ShadowHookData* sh_data,
	const SharedShadowHookData* shared_sh_data,
	void* guest_ip) 
{
  UNREFERENCED_PARAMETER(sh_data);

  if (!ShpIsShadowHookActive(shared_sh_data)) {
    return false;
  }

  //尋找指?, 指向對應HookInfo對象
  const auto info = ShpFindPatchInfoByAddress(shared_sh_data, guest_ip);
  if (!info) {
    return false;
  }

  // Update guest's IP
  // 把?發#BP Rip 指向對應對象的回?函數
  UtilVmWrite(VmcsField::kGuestRip, reinterpret_cast<ULONG_PTR>(info->handler));
  return true;
}

_Use_decl_annotations_
void MonitorPageChange(ShadowHookData* sh_data, const SharedShadowHookData* shared_sh_data, EptData* ept_data, ULONG64 CR3) 
{
	ULONG64 faultaddr = 0;
	ULONG64 newpa = 0;
	//HYPERPLATFORM_LOG_DEBUG("PageFault_Phy: %I64X PageFault_Vir: %I64X \r\n", sh_data->PageFault_Phy, sh_data->PageFault_Virt);
	for (auto& info : shared_sh_data->UserModeList) 
	{
		if (info->patch_address == (PVOID)sh_data->PageFault_Virt && CR3 == info->CR3) 
		{
			faultaddr = info->NewPhysicalAddress;
			if (faultaddr) 
			{
				ULONG64 newpa = 0;
				GetPhysicalAddressByNewCR3((PVOID)sh_data->PageFault_Virt, info->CR3, &newpa);
				HYPERPLATFORM_LOG_DEBUG("CR3: %I64X mapping changed from %I64X to %I64X ", CR3, faultaddr, newpa);

				if (faultaddr != newpa)
				{		
					//HYPERPLATFORM_LOG_DEBUG("CR3: %I64X mapping changed from %I64X to %I64X ", CR3, faultaddr, newpa);
					if (newpa) 
					{	
						//1. set new EPT-pte to read-only
						/*
						auto entry = EptGetEptPtEntry(ept_data, newpa);
						entry->fields.execute_access = TRUE;
						entry->fields.write_access = FALSE;
						entry->fields.read_access = FALSE;
						entry->fields.physial_address = UtilPfnFromPa(newpa);
						*/
						ModifyEPTEntryRWX(ept_data, newpa, newpa, FALSE, FALSE, TRUE);
						info->NewPhysicalAddress = newpa;
					}
						//2. reset old EPT-Pte to normal
						/*
						auto entry2 = EptGetEptPtEntry(ept_data, faultaddr);
						entry2->fields.execute_access = true;
						entry2->fields.write_access = true;
						entry2->fields.read_access = true;
						entry2->fields.physial_address = UtilPfnFromPa(faultaddr);
						*/
						sh_data->PageFault_Phy = 0;
						sh_data->PageFault_Virt = 0;
					}
				}
			}
		}
}
// Handles MTF VM-exit. Re-enables the shadow hook and clears MTF.
PKAPC_STATE apc;
_Use_decl_annotations_ void ShHandleMonitorTrapFlag(
    ShadowHookData* sh_data, 
	const SharedShadowHookData* shared_sh_data,
    EptData* ept_data) 
{	
	NT_VERIFY(ShpIsShadowHookActive(shared_sh_data));

	if (sh_data->CopyOnWrite)
	{
		ULONG64 guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
		MonitorPageChange(sh_data, shared_sh_data, ept_data, guest_cr3);
 		sh_data->CopyOnWrite = FALSE;
	}
	else if(!sh_data->IsKernelMemory)
	{
		const auto info = kRestoreLastHideInfo(sh_data);//get back last written EPT-Pte
		kEnableEntryForExecuteOnly(*info, ept_data);		     //turn back read-only	 
	}
	else if (sh_data->IsKernelMemory)
	{
		const auto info = ShpRestoreLastHookInfo(sh_data);//get back last written EPT-Pte
		ShpEnablePageShadowingForExec(*info, ept_data);		     //turn back read-only	 
	}
	ShpSetMonitorTrapFlag(sh_data, false);
} 

// Handles EPT violation VM-exit.
// old for hidden-hook queue
_Use_decl_annotations_ void ShHandleEptViolation(
												ShadowHookData* sh_data, 
												const SharedShadowHookData* shared_sh_data,
												EptData* ept_data,
												void* fault_va)
{

  if (!ShpIsShadowHookActive(shared_sh_data)) {
    return;
  }
  //尋找頁面
  const auto info = ShpFindPatchInfoByPage(shared_sh_data, fault_va);
  if (!info) {
    return;
  }
  // EPT violation was caused because a guest tried to read or write to a page
  // where currently set as execute only for protecting a hook. Let a guest
  // read or write a page from a read/write shadow page and run a single
  // instruction.

  ShpEnablePageShadowingForRW(*info, ept_data); //設置頁面可讀寫, 而所有EPT失效
  ShpSetMonitorTrapFlag(sh_data, true);			//設置MTF位,執行單步
  ShpSaveLastHookInfo(sh_data, *info);			//保存最新設置
}
//come here only copy-on-write
_Use_decl_annotations_ bool HandleCopyOnWrite(
	_In_ ShadowHookData* sh_data,
	_In_ const SharedShadowHookData* shared_sh_data, 
	_In_ ULONG_PTR fault_address,
	_In_ EptData* ept_data) 
{
	BOOLEAN ret = FALSE;
	ULONG64 guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);

	const PageFaultErrorCode fault_code = {
		static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode))
	};

	for (auto& info : shared_sh_data->UserModeList)
	{
		// fault va == our hidden va and CR3 is same (current process)
		if ((ULONG64)info->patch_address == fault_address &&  guest_cr3 == info->CR3)
		{ 
			//used for MTF handler for CopyOnWrite part 
			ULONG64 oldPa;
			GetPhysicalAddressByNewCR3(info->patch_address, info->CR3, &oldPa);

			sh_data->PageFault_Phy = oldPa;							//old pa
			sh_data->PageFault_Virt = (ULONG64)info->patch_address;	//va
			
			//after return Guest Os, Run a single instruction, and trap back into VMM
			sh_data->CopyOnWrite = TRUE;


			ModifyEPTEntryRWX(ept_data, oldPa, oldPa, TRUE, TRUE, TRUE);

			HYPERPLATFORM_LOG_DEBUG("[#PF Handler]sh_data->proc : 0x%I64X oldVA : %I64X oldPa: %I64X Reason: %X \r\n", PsGetCurrentProcess(),fault_address , oldPa, fault_code.all);
			ShpSetMonitorTrapFlag(sh_data, true);

			ret = TRUE;
		}
	}
	return ret;
}

// Handles EPT violation VM-exit.
// For hidden-variable / data  queue
BOOLEAN isLog;
//
_Use_decl_annotations_ bool kHandleEptViolation(
	ShadowHookData* sh_data, const SharedShadowHookData* shared_sh_data,
	EptData* ept_data, void* fault_va, bool IsExecute, bool IsWrite , bool IsRead) 
{ 

	if (!ShpIsShadowHookActive(shared_sh_data)) 
	{
		return false;
	}
	//find a page in var_hide list
	//const auto info = ShpFindHideInfoByPage(shared_sh_data, fault_va);
	const auto info = ShpFindHideInfoByProc(shared_sh_data, PsGetCurrentProcess());

	if (!info) {
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
_Use_decl_annotations_ EXTERN_C bool ShInstallHide(
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
	 //PAGED_CODE();
	  //1. getting original page; 
	  auto info = ShpCreateHookInformation(shared_sh_data, reinterpret_cast<void*>(address), target, name);
	  if (!info) {
		  return false;
	  }

	  // Write a 0xCC with instruction len. 
	  // 2. write 0xCC into original 
	  if (!ShpSetupInlineHook(info->patch_address, info->shadow_page_base_for_exec->page, &target->original_call)) {
		  return false;
	  }

	  HYPERPLATFORM_LOG_DEBUG(
		  "Patch = %p, Exec = %p, RW = %p, Trampoline = %p", info->patch_address,
		  info->shadow_page_base_for_exec->page + BYTE_OFFSET(info->patch_address),
		  info->shadow_page_base_for_rw->page + BYTE_OFFSET(info->patch_address),
		  target->original_call);

	  //把是次HOOK的INFO壓入到最後
	  shared_sh_data->KernelModeList.push_back(std::move(info));
 
  return true;
}

// Creates or reuses a couple of copied pages and initializes HookInformation
_Use_decl_annotations_ static std::unique_ptr<HookInformation>
ShpCreateHookInformation(SharedShadowHookData* shared_sh_data, void* address,
                         ShadowHookTarget* target, const char* name) {
  auto info = std::make_unique<HookInformation>();
  
  //find a page by comparing patch address (va)
  auto reusable_info = ShpFindPatchInfoByPage(shared_sh_data, address);
  
  //if exist a page that we hooked, use it.
  if (reusable_info) { 
    // Found an existing HookInformation object targetting the same page as this
    // one. re-use shadow pages.
    info->shadow_page_base_for_rw = reusable_info->shadow_page_base_for_rw;
    info->shadow_page_base_for_exec = reusable_info->shadow_page_base_for_exec;
  } 

  //if not exist a page that we hooked, allocate it.
  else {  

    // This hook is for a page that is not currently have any KernelModeList (ie not
    // shadowed). Creates shadow pages.
    info->shadow_page_base_for_rw = std::make_shared<Page>();
    info->shadow_page_base_for_exec = std::make_shared<Page>();
	
	//aligning the page
    auto page_base = PAGE_ALIGN(address);

	//copy memory from page base 
    RtlCopyMemory(info->shadow_page_base_for_rw->page, page_base, PAGE_SIZE);
    RtlCopyMemory(info->shadow_page_base_for_exec->page, page_base, PAGE_SIZE);
  }

  //patch address of Inline hook
  info->patch_address = address;
  
  //Store PA of a page base (VA) of created / retrieved page. (I.e  Original Page/ Hooked Page respectively)
  info->pa_base_for_rw = UtilPaFromVa(info->shadow_page_base_for_rw->page);
  
  //Store PA of a page base (VA) of created / retrieved page. (I.e  Original Page/ Hooked Page respectively)
  info->pa_base_for_exec = UtilPaFromVa(info->shadow_page_base_for_exec->page);
  
  //hook handler
  info->handler = target->handler;
 
  //hook名稱
  RtlCopyMemory(info->name.data(), name, info->name.size() - 1);
  
  return info;
}
// Builds a trampoline code for calling an orignal code and embeds 0xcc on the
// shadow_exec_page + 掛勾地址的偏移 = 0xCC
// 掛勾地址 = 被inline hook
_Use_decl_annotations_ EXTERN_C static bool ShpSetupInlineHook(
    void* patch_address,		//要掛勾的地址
	UCHAR* shadow_exec_page,	//Retrieved/Created(Hooked / Original Page)
	void** original_call_ptr	//原函數調用HOOK位置指令+下一句指令
) {
  PAGED_CODE();

  //從目標地址取指令長度
  const auto patch_size = ShpGetInstructionSize(patch_address);
  if (!patch_size) {
    return false;
  }

  // Build trampoline code (copied stub -> in the middle of original)
  //HOOK指令的下一句指令
  //生成遠跳指令
  const auto jmp_to_original = ShpMakeTrampolineCode(reinterpret_cast<UCHAR*>(patch_address) + patch_size);

#pragma warning(push)
#pragma warning(disable : 30030)  // Allocating executable POOL_TYPE memory

  const auto original_call = ExAllocatePoolWithTag(NonPagedPoolExecute, 
								  patch_size + sizeof(jmp_to_original),
								  kHyperPlatformCommonPoolTag);
#pragma warning(pop)
  if (!original_call) {
    return false;
  }

  // Copy original code and embed jmp code following original code
  //保存原有代碼
  RtlCopyMemory(original_call, patch_address, patch_size);
#pragma warning(push)
#pragma warning(disable : 6386) 
  // 90
  // FF 25 00 00 00 00 
  // handler
 
  RtlCopyMemory(reinterpret_cast<UCHAR*>(original_call) + patch_size, &jmp_to_original, sizeof(jmp_to_original));
#pragma warning(pop)

  // install patch to shadow page
  static const UCHAR kBreakpoint[] = {
      0xcc,
  };
  //要hook的指令長度 
  //影子頁面+hook地址偏移 寫入0xCC
   RtlCopyMemory(shadow_exec_page + BYTE_OFFSET(patch_address), kBreakpoint, sizeof(kBreakpoint));

  //清除cpu緩存
  KeInvalidateAllCaches();

  //HOOK的地址
  *original_call_ptr = original_call;
  return true;
}

// Returns a size of an instruction at the address
_Use_decl_annotations_ EXTERN_C static SIZE_T ShpGetInstructionSize(
    void* address) {
  PAGED_CODE();

  // Save floating point state
  KFLOATING_SAVE float_save = {};
  auto status = KeSaveFloatingPointState(&float_save);
  if (!NT_SUCCESS(status)) {
    return 0;
  }

  // Disassemble at most 15 bytes to get an instruction size
  csh handle = {};
  const auto mode = IsX64() ? CS_MODE_64 : CS_MODE_32;
  if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
    KeRestoreFloatingPointState(&float_save);
    return 0;
  }

  static const auto kLongestInstSize = 15;
  cs_insn* instructions = nullptr;
  const auto count =
      cs_disasm(handle, reinterpret_cast<uint8_t*>(address), kLongestInstSize,
                reinterpret_cast<uint64_t>(address), 1, &instructions);
  if (count == 0) {
    cs_close(&handle);
    KeRestoreFloatingPointState(&float_save);
    return 0;
  }

  // Get a size of the first instruction
  const auto size = instructions[0].size;
  cs_free(instructions, count);
  cs_close(&handle);

  // Restore floating point state
  KeRestoreFloatingPointState(&float_save);
  return size;
}

// Returns code bytes for inline hooking
_Use_decl_annotations_ EXTERN_C static TrampolineCode ShpMakeTrampolineCode(void* hook_handler) {
  PAGED_CODE();

#if defined(_AMD64_)
  // 90               nop
  // ff2500000000     jmp     qword ptr cs:jmp_addr
  // jmp_addr:
  // 0000000000000000 dq 0
  return {
      0x90,
      {
          0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
      },
      hook_handler,
  };
#else
  // 90               nop
  // 6832e30582       push    offset nt!ExFreePoolWithTag + 0x2 (8205e332)
  // c3               ret
  return {
      0x90, 0x68, hook_handler, 0xc3,
  };
#endif
}

// Find a HookInformation instance by address
// 
_Use_decl_annotations_ static HookInformation* ShpFindPatchInfoByPage(
    const SharedShadowHookData* shared_sh_data, void* address)
{
 const auto found = std::find_if(shared_sh_data->KernelModeList.cbegin(), shared_sh_data->KernelModeList.cend(),[address](const auto& info) {
        return PAGE_ALIGN(info->patch_address) == PAGE_ALIGN(address);
      });
  if (found == shared_sh_data->KernelModeList.cend()) {
    return nullptr;
  }
  return found->get();
}
_Use_decl_annotations_ static HideInformation* ShpFindHideInfoByProc(const SharedShadowHookData* shared_sh_data, void* Proc)
{
	const auto found = std::find_if(shared_sh_data->UserModeList.cbegin(), shared_sh_data->UserModeList.cend(), [Proc](const auto& info) {
		return info->proc == Proc;
	});
	if (found == shared_sh_data->UserModeList.cend()) {
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
// Find a HookInformation instance that are on the same page as the address
_Use_decl_annotations_ static HookInformation* ShpFindPatchInfoByAddress(const SharedShadowHookData* shared_sh_data, void* address) 
{
  auto found = std::find_if
  (
      shared_sh_data->KernelModeList.cbegin(), shared_sh_data->KernelModeList.cend(),
      [address](const auto& info)
	  {
		return info->patch_address == address; 
  	  }
  );
  
  if (found == shared_sh_data->KernelModeList.cend()) 
  {
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
	else 
	{
	// ring-0 write
		const auto ept_pt_entry = EptGetEptPtEntry(ept_data, UtilPaFromVa(info.patch_address));
		ept_pt_entry->fields.write_access = true;
		ept_pt_entry->fields.read_access  = true;
		ept_pt_entry->fields.physial_address = UtilPfnFromPa(info.pa_base_for_exec);		
	// ring-0 write
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
	else 
	{
		// ring-0 write
		const auto ept_pt_entry = EptGetEptPtEntry(ept_data, UtilPaFromVa(info.patch_address));
		ept_pt_entry->fields.write_access = true;
		ept_pt_entry->fields.read_access = true;
		ept_pt_entry->fields.physial_address = UtilPfnFromPa(info.pa_base_for_rw);
		// ring-0 write
	}
	UtilInveptAll();
}

//Sushi work
_Use_decl_annotations_ static void ShpEnablePageShadowingForExec(const HookInformation& info, EptData* ept_data) 
{
	const auto ept_pt_entry = EptGetEptPtEntry(ept_data, UtilPaFromVa(info.patch_address));
	ept_pt_entry->fields.write_access = false;
	ept_pt_entry->fields.read_access = false;
	ept_pt_entry->fields.physial_address = UtilPfnFromPa(info.pa_base_for_exec); 
	UtilInveptAll();
}
//Sushi work
_Use_decl_annotations_ static void ShpEnablePageShadowingForRW(const HookInformation& info, EptData* ept_data) 
{
  const auto ept_pt_entry = EptGetEptPtEntry(ept_data, UtilPaFromVa(info.patch_address));
  ept_pt_entry->fields.write_access   = true;
  ept_pt_entry->fields.read_access    = true;
  ept_pt_entry->fields.physial_address = UtilPfnFromPa(info.pa_base_for_rw);
  UtilInveptAll();
}

_Use_decl_annotations_ static void ShpDisablePageShadowing(const HookInformation& info, EptData* ept_data) 
{
  const auto pa_base = UtilPaFromVa(PAGE_ALIGN(info.patch_address));
  const auto ept_pt_entry = EptGetEptPtEntry(ept_data, pa_base);
  ept_pt_entry->fields.write_access = true;
  ept_pt_entry->fields.read_access = true;
  ept_pt_entry->fields.physial_address = UtilPfnFromPa(pa_base);
  UtilInveptAll();
}
// 
_Use_decl_annotations_ static void kDisableVarHiding(const HideInformation& info, EptData* ept_data)
{
	// ring-3 start 
	ULONG64 newPA = 0;
	GetPhysicalAddressByNewCR3(info.patch_address, info.CR3, &newPA);
	ModifyEPTEntryRWX(ept_data, newPA, info.pa_base_for_rw, TRUE, TRUE, TRUE);
	UtilInveptAll();
}
// Set MTF on the current processor
// 置單步異常 
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
// Checks if DdiMon is already initialized
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