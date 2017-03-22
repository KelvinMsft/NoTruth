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
#include "MemoryHide.h"
#include "Ring3Hide.h"
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

#define TargetAppName "notepad.exe"
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
	
	HYPERPLATFORM_LOG_INFO("locked Memory \r\n");

	return mdl;
}
//--------------------------------------------------------------------------------------//
void UnLockMemory(
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

	HYPERPLATFORM_LOG_INFO("Unlocked Memory \r\n");

}


extern "C" { 
	 PCHAR PsGetProcessImageFileName(PEPROCESS);
}
//--------------------------------------------------------------------------------------//
NTSTATUS AddMemoryHide(PEPROCESS proc, ULONG64 Address) {
	
	KAPC_STATE ApcState; 
	ULONG64			cr3; 
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	PMDLX		mdl = NULL;
	KeStackAttachProcess(proc, &ApcState);

	cr3 = __readcr3(); 

	//ensure resides in physical memory 
	mdl = LockMemory((PVOID)Address, PAGE_SIZE, &ApcState);

	if (TruthCreateNewHiddenNode(
		reinterpret_cast<ShareDataContainer*>(sharedata), //included two list var_hide and hook_hide
		(PVOID)Address,										//Ring-3 hidden address, PE-Header 
		"calcEproc",										//name 
		MmGetPhysicalAddress((PVOID)Address).QuadPart,		//Physical address used for Copy-On-Write
		cr3,
		mdl,
		proc
	))
	{
		status = STATUS_SUCCESS;
	}
	 
	KeUnstackDetachProcess(&ApcState);

	return status;
}

//--------------------------------------------------------------------------------------//
NTSTATUS StartMemoryHide()
{ 
	return kStartHiddenEngine(); 
}

//--------------------------------------------------------------------------------------//
NTSTATUS StopMemoryHide()
{
	return kStopHiddenEngine();
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
		HYPERPLATFORM_LOG_INFO("Process %s Exiting...  \r\n", procName);

		if (Create) 
		{ 
			// do nothing.
		}
		else
		{
			HYPERPLATFORM_LOG_INFO("Process Exiting... \r\n");
			PMDLX mdl = GetHideMDL(reinterpret_cast<ShareDataContainer*>(sharedata), proc);
		 
			//hyper-call
			kDisableHideByProcess(proc);
			 
			if (mdl)
			{
				KAPC_STATE apcstate;
				UnLockMemory(proc, &apcstate, mdl); 
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
  HYPERPLATFORM_LOG_INFO("NoTruth has been terminated.");
}
//--------------------------------------------------------------------------------------//
 