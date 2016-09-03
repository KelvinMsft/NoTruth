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
#include "../../DdiMon/ddi_mon.h"
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

#define DDI_WIN32_DEVICE_NAME_A		"\\\\.\\DdiMon"
#define DDI_WIN32_DEVICE_NAME_W		L"\\\\.\\DdiMon"
#define DDI_DEVICE_NAME_A			"\\Device\\DdiMon"
#define DDI_DEVICE_NAME_W			L"\\Device\\DdiMon"
#define DDI_DOS_DEVICE_NAME_A		"\\DosDevices\\DdiMon"
#define DDI_DOS_DEVICE_NAME_W		L"\\DosDevices\\DdiMon"
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
PEPROCESS hiddenProc;
NTSTATUS DispatchHideEngineIOCTL(
			IN PVOID InputBuffer,				//輸入
			IN ULONG InputBufferLength,			//輸入buffer大小
			IN PVOID OutputBuffer,				//輸出
			IN ULONG OutputBufferLength,		//輸出buffer大小
			IN ULONG IoControlCode,
			IN PIO_STATUS_BLOCK pIoStatus)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTRANSFERIOCTL data = (PTRANSFERIOCTL)InputBuffer;
	PEPROCESS oldProc = PsGetCurrentProcess();
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
	HYPERPLATFORM_LOG_DEBUG("Hide engine IOCTL Dispatching %x %X\r\n", IoControlCode, IOCTL_HIDE);
	HYPERPLATFORM_LOG_DEBUG("ret\r\n");
	return status;
}
NTSTATUS DDI_devCtrlRoutine(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
)
{
	NTSTATUS			status = STATUS_SUCCESS;				//默认返回值、状态
	PIO_STATUS_BLOCK	ioStatus;								//IRP的IO状态
	PIO_STACK_LOCATION	pIrpStack;								//当前的IRP栈
	PDEVICE_EXTENSION	deviceExtension;
	PVOID				inputBuffer, outputBuffer;				//输入、输出缓冲区
	ULONG				inputBufferLength, outputBufferLength;	//输入、输出缓冲区的大小
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
		//io控制函数
		DispatchHideEngineIOCTL(inputBuffer,	//输入缓冲区
			inputBufferLength,		//输入缓冲区大小
			outputBuffer,			//输出缓冲区
			outputBufferLength,		//输出缓冲区大小
			ioControlCode,			//功能号
			ioStatus);				//IRP的IO状态
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

/*** 
  // Virtualize all processors 虛擬化所有CPU
 
  // 透過DPC, 分發虛擬化回調
  // 虛擬化過程大致流程如下:
  
  // 對於當前CPU (回?為:vmpstartVM)
  // 1. 分配ProcessorData結構
  // 2. ProcessorData->ept_data << 構建EPT?表
  // 3. ProcessorData->sh_data  << 分配及初始化ShadowHookData ??勾子?細?料
  // 4. 分配vmm用的棧
  // 5. 從分配到的地址,加上大小 = 棧?域地址 (因為棧是向下發展)
  // 6. 壓入ProcessorData指?
  // 7. 再壓入MAXULONG_PTR
  // 8. 以後就是可用的真正棧基址及空?
  // 9. Processor_data->shared_data << shared_data 參數上下文
  //10. 分配VMX-Region 及 VMCS, 它們的維?結構同一?->?而初始化填充vmcs各?域-> 如?置VMEXIT回?函數 -> 其中函數VmmVmExitHandler為核心, 分發exit原因
  //11. 啟動-> vmcs?置後 -> ?用匯編VMLAUNCH指令, 啟動VM

  完成?擬化後 激活HOOK流程
  流程如下:
  // 遍歷內核導出表, 找到函數地址後, ?用回?
  // 遍歷準備了HOOK的全局數組, 數組結構為ShadowHookTarget[] (函數名,HOOK回?,原函數)
  // ShInstallHook安?勾子, 參數為SharedShadowHookData(已HOOK了的數組,減小重覆分配相同?面)
  // ShpCreateHookInformation 嘗?透?shared_sh_data?取或創建兩??面 執行/?寫 , 因為不同CPU核心可能一早已經分配影子?面
  // ShpSetupInlineHook, 基本?置INLINE HOOK後, 參數為分配好的可執行?面, 對?一?寫下0xCC
  // (即現在有兩? , 1?為原來?面(已被INLINE HOOK), 1?為影子執行?面(寫入0xCC))
  // 最後把HOOKINFO元素插入全局數組

	真實?面    : INLINE HOOK
	影子執行?面: 寫入了0xCC
	影子?寫?面: 正常無修改?面

	?寫的情況:

	1. 把映射EPT?和?擬內存?聯 

	2. ?置EPT?屬性為不可?寫,並EPT??為無效 

	3. 任何?程?問不可?寫內存的EPT?, 導致陷入VMM 

	4. ?入EPT????問?理函數

	5. 更換?面為可?寫,同時返回

	6. 把EPT?對應的物理地址修改為"影子?寫?面"

	7. ?置MTF位,產生單步 

	8. 捕?單步異常 

	9. ?置"影子執行?面", 再?置?EPT?為不可?寫及EPT?無效, ?下次有人?問時仍然重覆以第一步


	執行的情況: 

	1. 執行地址

	2. ?發斷?異常

	3. 捕?斷? 

	4. 修改EIP到??函數, 跳到我們的函數

	5. 返回原函數



*
*
*
*/
// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
	BOOLEAN symbolicLink;
	UNICODE_STRING		ntDeviceName;
	UNICODE_STRING		dosDeviceName;
 
	PDEVICE_EXTENSION		deviceExtension = NULL; 
	

  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();
  
  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\DdiMon.log";
  
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
  //初始化所有內存塊, VM初始化EPT時侯會使用到
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

