// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements NoTruth functions.

#include "NoTruth.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "Wdm.h"
#include "ntddk.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <array>
#include "shadow_hook.h"
#include "Ring3Hide.h"
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

#define TargetAppName "calc.exe"
#define TargetAppName2 "VTxRing3.exe"

////////////////////////////////////////////////////////////////////////////////
//
// global variable
// 
extern ShareDataContainer* sharedata;


////////////////////////////////////////////////////////////////////////////////
//
// types
//
// A helper type for parsing a PoolTag value
union PoolTag {
  ULONG value;
  UCHAR chars[4];
};


////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, NoTruthInitialization)
#pragma alloc_text(PAGE, NoTruthTermination)
#endif

typedef struct _SECURITY_ATTRIBUTES {
	DWORD  nLength;
	PVOID  lpSecurityDescriptor;
	CHAR   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;


//--------------------------------------------------------------------/
PMDLX LockMemory(
	PVOID startAddr,
	ULONG len,
	PEPROCESS proc,
	PKAPC_STATE apcstate
)
{
	PMDLX mdl = NULL;

	// Attach to process to ensure virtual addresses are correct

	// Create MDL to represent the image
	mdl = IoAllocateMdl(startAddr, (ULONG)len, FALSE, FALSE, NULL);

	if (mdl == NULL)
		return NULL;

	// Attempt to probe and lock the pages into memory

	MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
	

	return mdl;
}
//--------------------------------------------------------------------------------------//
void pagingUnlockProcessMemory(
	PEPROCESS proc,
	PKAPC_STATE apcstate, 
	PMDLX mdl
)
{
	// Attach to process to ensure virtual addresses are correct
	KeStackAttachProcess(proc, apcstate);

	// Unlock & free MDL and corresponding pages
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	KeUnstackDetachProcess(apcstate);
}


extern "C" { 
	 PCHAR PsGetProcessImageFileName(PEPROCESS);
}
//--------------------------------------------------------------------------------------//
VOID HiddenStartByIOCTL(PEPROCESS proc, ULONG64 Address) {
	
	KAPC_STATE K; 
	ULONG64 cr3; 

	KeStackAttachProcess(proc, &K);
	cr3 = __readcr3(); 
	//ensure physical memory
	PMDLX mdl = LockMemory((PVOID)Address, PAGE_SIZE, proc, &K);

	kInitHiddenEngine(
		reinterpret_cast<ShareDataContainer*>(sharedata), //included two list var_hide and hook_hide
		(PVOID)Address,										//Ring-3 hidden address, PE-Header
		0,													//used for callback
		"calcEproc",										//name
		true,												//var_hide/ hook_hide list 
		true,												//Is Ring3 or Ring 0 (TRUE/FALSE)?
		MmGetPhysicalAddress((PVOID)Address).QuadPart,		//Physical address used for Copy-On-Write
		cr3,
		mdl,
		proc
	);
	kStartHiddenEngine();
	KeUnstackDetachProcess(&K);
}

//--------------------------------------------------------------------------------------//
VOID ProcessMonitor(
	IN HANDLE  ParentId,
	IN HANDLE  ProcessId,
	IN BOOLEAN  Create)
{
	char *procName;
	PEPROCESS proc;
	PsLookupProcessByProcessId(ProcessId, &proc);
	procName = PsGetProcessImageFileName(proc);

	if (strncmp(TargetAppName, procName, strlen(TargetAppName)) == 0||
		strncmp(TargetAppName2, procName, strlen(TargetAppName2)) == 0)
	{
		if (Create) 
		{

		}
		else
		{
			PMDLX mdl = GetHideMDL(reinterpret_cast<ShareDataContainer*>(sharedata), proc);
			SetTerminateProcess(reinterpret_cast<ShareDataContainer*>(sharedata), proc);
			kDisableHideByProcess(proc);
			if (mdl) {
				KAPC_STATE apcstate;
				pagingUnlockProcessMemory(proc, &apcstate, mdl);
			}
		}
	}
}

//--------------------------------------------------------------------------------------//
_Use_decl_annotations_ EXTERN_C NTSTATUS NoTruthInitialization(ShareDataContainer* shared_sh_data) 
{
  PAGED_CODE();

  NTSTATUS status = STATUS_SUCCESS; 
  PsSetCreateProcessNotifyRoutine(ProcessMonitor, FALSE);
  return status;
}
//--------------------------------------------------------------------------------------//
// Terminates NoTruth
_Use_decl_annotations_ EXTERN_C void NoTruthTermination() {
  PAGED_CODE();

  kStopHiddenEngine();
  PsSetCreateProcessNotifyRoutine(ProcessMonitor, TRUE);
  UtilSleep(500);
  HYPERPLATFORM_LOG_INFO("NoTruth has been terminated.");
}
//--------------------------------------------------------------------------------------//
 