// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "log.h"
#include "util.h"
#include "vm.h"
#ifndef HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1
#endif  // HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#include "performance.h"
#include "../../NoTruth/NoTruth.h"
struct Page1 {
	UCHAR* page;
	Page1();
	~Page1();
};
typedef struct _TRANSFER_IOCTL
{
	ULONG64 ProcID;
	ULONG64 HiddenType;
	ULONG64 Address;
}TRANSFERIOCTL, *PTRANSFERIOCTL;

#define DDI_WIN32_DEVICE_NAME_A		"\\\\.\\NoTruth"
#define DDI_WIN32_DEVICE_NAME_W		L"\\\\.\\NoTruth"
#define DDI_DEVICE_NAME_A			"\\Device\\NoTruth"
#define DDI_DEVICE_NAME_W			L"\\Device\\NoTruth"
#define DDI_DOS_DEVICE_NAME_A		"\\DosDevices\\NoTruth"
#define DDI_DOS_DEVICE_NAME_W		L"\\DosDevices\\NoTruth"
typedef struct _DEVICE_EXTENSION
{
	ULONG  StateVariable;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

ULONG64 G_cr3;
UCHAR* testpool;
extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//
PDEVICE_OBJECT		deviceObject = NULL;
////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//
#define IOCTL_TRANSFER_TYPE( _iocontrol)   (_iocontrol & 0x3)

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
//--------------------------------------------------------------------------------------//
NTSTATUS DispatchHideEngineIOCTL(
			IN PVOID InputBuffer,				
			IN ULONG InputBufferLength,			
			IN PVOID OutputBuffer,				
			IN ULONG OutputBufferLength,		
			IN ULONG IoControlCode,
			IN PIO_STATUS_BLOCK pIoStatus)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTRANSFERIOCTL data = (PTRANSFERIOCTL)InputBuffer;
	PEPROCESS hiddenProc; 
	if (IoControlCode == IOCTL_HIDE) 
	{
		HYPERPLATFORM_LOG_DEBUG("[HIDE]Hide engine IOCTL Dispatching %x \r\n" , IoControlCode);
	}
	if (data)
	{
		HYPERPLATFORM_LOG_DEBUG("Proc ID: %I64X Address : %I64X", data->ProcID, data->Address);
		PsLookupProcessByProcessId((HANDLE)data->ProcID, &hiddenProc);
		HiddenStartByIOCTL(hiddenProc, data->Address);
	}
	return status;
}
//--------------------------------------------------------------------------------------//
NTSTATUS DDI_devCtrlRoutine(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
)
{
	NTSTATUS			status = STATUS_SUCCESS;				
	PIO_STATUS_BLOCK	ioStatus;								
	PIO_STACK_LOCATION	pIrpStack;								
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				inputBuffer, outputBuffer;				
	ULONG				inputBufferLength, outputBufferLength;	
	ULONG				ioControlCode;

	/*	dprintf("[$XTR]--->IrpMjXTRdevCtrlRoutine( 0x%08x, 0x%08x ).\n", DeviceObject, Irp);*/

	pIrpStack = IoGetCurrentIrpStackLocation(Irp);
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	ioStatus = &Irp->IoStatus;
	ioStatus->Status = STATUS_SUCCESS;	// Assume success
	ioStatus->Information = 0;              // Assume nothing returned

											//
											// Get the pointer to the input/output buffer and it's length
	inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;


	switch (pIrpStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrint("[$ARK]<-IRP_MJ_CREATE.\n");
		break;

	case IRP_MJ_CLOSE:
		DbgPrint("[$ARK]->IRP_MJ_CLOSE.\n");
		break;

	case IRP_MJ_SHUTDOWN:
		DbgPrint("[$ARK] IRP_MJ_SHUTDOWN.\n");
		break;

	case IRP_MJ_DEVICE_CONTROL:
		if (IOCTL_TRANSFER_TYPE(ioControlCode) == METHOD_NEITHER)
		{
			DbgPrint("[$ARK] METHOD_NEITHER\n");
			outputBuffer = Irp->UserBuffer;
		}

		//
		DbgPrint("[$XTR] IRP_MJ_DEVICE_CONTROL->IrpMjXTRdevCtrlRoutine(DeviceObject=0x%08x, Irp=0x%08x)->ARKioControl().\n", DeviceObject, Irp);

		DispatchHideEngineIOCTL(inputBuffer,	
			inputBufferLength,		
			outputBuffer,			
			outputBufferLength,		
			ioControlCode,			
			ioStatus);				
		break;
	}

	//
	// TODO: if not pending, call IoCompleteRequest and Irp is freed.
	//

	Irp->IoStatus.Status = ioStatus->Status;
	Irp->IoStatus.Information = ioStatus->Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return  status;
}

// A driver entry point
//--------------------------------------------------------------------------------------//
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
	BOOLEAN symbolicLink;
	UNICODE_STRING		ntDeviceName;
	UNICODE_STRING		dosDeviceName;
 
	PDEVICE_EXTENSION		deviceExtension = NULL; 
	

  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();
  
  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\NoTruth.log";
  
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;
 
  auto status = STATUS_UNSUCCESSFUL;
  int i = 0;

 // testpool = reinterpret_cast<UCHAR*>(ExAllocatePoolWithTag(
//	  NonPagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));
  testpool = reinterpret_cast<UCHAR*>(ExAllocatePool(
	  NonPagedPool, PAGE_SIZE));

  RtlFillMemory(testpool, 1024, 0x90);
  
  driver_object->DriverUnload = DriverpDriverUnload;

  
  //HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
    return STATUS_CANCELLED;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    LogTermination();
    return status;
  }

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    LogTermination();	
    return status;
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }
  
  RtlInitUnicodeString(&ntDeviceName, DDI_DEVICE_NAME_W);
  
  status = IoCreateDevice(
	  driver_object,
	  sizeof(DEVICE_EXTENSION),		// DeviceExtensionSize
	  &ntDeviceName,					// DeviceName
	  FILE_DEVICE_UNKNOWN,			// DeviceType
	  0,								// DeviceCharacteristics
	  TRUE,							// Exclusive
	  &deviceObject					// [OUT]
  );

  if (!NT_SUCCESS(status))
  {
	  DbgPrint("[$XTR] IoCreateDevice failed(0x%x).\n", status);
	  return FALSE;
  }

  //设置设备的读写模式
  deviceObject->Flags |= DO_BUFFERED_IO;	//缓冲区读写
											//设置设备的扩展数据
  deviceExtension = (PDEVICE_EXTENSION)deviceObject->DeviceExtension;
   
  RtlInitUnicodeString(&dosDeviceName, DDI_DOS_DEVICE_NAME_W);

  status = IoCreateSymbolicLink(&dosDeviceName, &ntDeviceName);

  if (!NT_SUCCESS(status))
  {
	  DbgPrint("[$XTR] IoCreateSymbolicLink failed(0x%x).\n", status);
	  return FALSE;
  }
	
  symbolicLink = TRUE;

  driver_object->MajorFunction[IRP_MJ_CREATE] = 
  driver_object->MajorFunction[IRP_MJ_CLOSE] =
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DDI_devCtrlRoutine;
   
  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();
  UNICODE_STRING		ntDeviceName;
  UNICODE_STRING		dosDeviceName;
  RtlInitUnicodeString(&dosDeviceName, DDI_DOS_DEVICE_NAME_W);
  driver_object->DeviceObject = deviceObject;
  IoDeleteDevice(deviceObject);
  IoDeleteSymbolicLink(&dosDeviceName );

  VmTermination();
  UtilTermination();
  PerfTermination();
  LogTermination();
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"

