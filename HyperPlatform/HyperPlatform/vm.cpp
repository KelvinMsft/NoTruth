// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements VMM initialization functions.

#include "vm.h"
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "ept.h"
#include "log.h"
#include "util.h"
#include "vmm.h"
#include "../../DdiMon/ddi_mon.h"
#include "../../DdiMon/shadow_hook.h"

extern "C" {
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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpIsVmxAvailable();

_IRQL_requires_(DISPATCH_LEVEL) static NTSTATUS
    VmpSetLockBitCallback(_In_opt_ void *context);

_IRQL_requires_max_(PASSIVE_LEVEL) static SharedProcessorData *VmpInitializeSharedData();

_IRQL_requires_(DISPATCH_LEVEL) static NTSTATUS VmpStartVM(_In_opt_ void *context);

static void VmpInitializeVm(_In_ ULONG_PTR guest_stack_pointer,
                            _In_ ULONG_PTR guest_instruction_pointer,
                            _In_opt_ void *context);

static bool VmpEnterVmxMode(_Inout_ ProcessorData *processor_data);

static bool VmpInitializeVMCS(_Inout_ ProcessorData *processor_data);

static bool VmpSetupVMCS(_In_ const ProcessorData *processor_data,
                         _In_ ULONG_PTR guest_stack_pointer,
                         _In_ ULONG_PTR guest_instruction_pointer,
                         _In_ ULONG_PTR vmm_stack_pointer);

static void VmpLaunchVM();

static ULONG VmpGetSegmentAccessRight(_In_ USHORT segment_selector);

static SegmentDesctiptor *VmpGetSegmentDescriptor(
    _In_ ULONG_PTR descriptor_table_base, _In_ USHORT segment_selector);

static ULONG_PTR VmpGetSegmentBaseByDescriptor(
    _In_ const SegmentDesctiptor *segment_descriptor);

static ULONG_PTR VmpGetSegmentBase(_In_ ULONG_PTR gdt_base,
                                   _In_ USHORT segment_selector);

static ULONG VmpAdjustControlValue(_In_ Msr msr, _In_ ULONG requested_value);

static NTSTATUS VmpStopVM(_In_opt_ void *context);

static KSTART_ROUTINE VmpVmxOffThreadRoutine;

static void VmpFreeProcessorData(_In_opt_ ProcessorData *processor_data);

static bool VmpIsVmmInstalled();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, VmInitialization)
#pragma alloc_text(INIT, VmpIsVmxAvailable)
#pragma alloc_text(INIT, VmpSetLockBitCallback)
#pragma alloc_text(INIT, VmpInitializeSharedData)
#pragma alloc_text(INIT, VmpStartVM)
#pragma alloc_text(INIT, VmpInitializeVm)
#pragma alloc_text(INIT, VmpEnterVmxMode)
#pragma alloc_text(INIT, VmpInitializeVMCS)
#pragma alloc_text(INIT, VmpSetupVMCS)
#pragma alloc_text(INIT, VmpLaunchVM)
#pragma alloc_text(INIT, VmpGetSegmentAccessRight)
#pragma alloc_text(INIT, VmpGetSegmentBase)
#pragma alloc_text(INIT, VmpGetSegmentDescriptor)
#pragma alloc_text(INIT, VmpGetSegmentBaseByDescriptor)
#pragma alloc_text(INIT, VmpAdjustControlValue)
#pragma alloc_text(PAGE, VmTermination)
#pragma alloc_text(PAGE, VmpVmxOffThreadRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Define GetSegmentLimit if it is not defined yet (it is only defined on x64)
#if !defined(GetSegmentLimit)
inline ULONG GetSegmentLimit(_In_ ULONG selector) {
  return __segmentlimit(selector);
}
#endif

// Checks if a VMM can be installed, and so, installs it

//初始化整個VM機制
// 1. 檢測是否已經安裝VM
// 2. 檢測機器是否支持VT
// 3. 初始化HOOKDATA,和自定義的一份MSR
// 4. 遍歷每一個核心, 利用vmcall回調 使進入VMM
// 5. 進入VMM後
SharedShadowHookData* sharedata;
_Use_decl_annotations_ NTSTATUS VmInitialization() {
  //頁面對齊
  PAGED_CODE();

  //判斷是否已經安裝vm
  if (VmpIsVmmInstalled()) {
    return STATUS_CANCELLED;
  }
  //通?CPUID判斷是否VMX可用
  if (!VmpIsVmxAvailable()) {
    return STATUS_HV_FEATURE_UNAVAILABLE;
  }
  //初始化MSR-Bitmap並建立一份空的HOOKDATA數組
  //Prepared a MST-Bitmap and EMPTY HOOKDATA data array

  const auto shared_data = VmpInitializeSharedData();
  if (!shared_data) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  // Virtualize all processors
 
  // 透過DPC, 分發虛擬化回調
  // 虛擬化過程大致流程如下:
  
  // 對於當前CPU (回調為:vmpstartVM)
  // 1. 分配ProcessorData
  // 2. ProcessorData->ept_data << 構建EPT頁表
  // 3. ProcessorData->sh_data  << 分配及初始化ShadowHookData , 保留最後處理的一次數據
  // 4. 分配vmm用的棧
  // 5. 從分配到的地址,加上大小 = 棧起始地址 (因為棧是向下發展)
  // 6. 壓入ProcessorData指針
  // 7. 再壓入MAXULONG_PTR
  // 8. 以後就是可用的真正棧基址及空間
  // 9. Processor_data->shared_data << shared_data 參數上下文
  //10. 分配VMX-Region 及 VMCS, 它們的維護結構同一?->從而初始化填充vmcs各個域-> 如設置VMEXIT回調函數 -> 其中函數VmmVmExitHandler為核心, 分發exit原因
  //11. 啟動-> vmcs設置後 -> 用匯編VMLAUNCH指令, 啟動VM

  //
  //因此: 每一個CPU都有自己一份數據.....
  //其中包括: 
  //1. cpu自己的棧空間大小等..
  //2. ept頁表(processor_data->ept_data)							 
  //3. 最後一次處理的EPT_Violation數據(processor_data->sh_data)   ; EPT_Violation時保存, MTF時恢復
  //4. 共用的hook code/hide data數組(shared_data->shared_sh_data ; 用於EPT_violation時
  auto status = UtilForEachProcessor(VmpStartVM, shared_data);
  if (!NT_SUCCESS(status)) {
    UtilForEachProcessor(VmpStopVM, nullptr);
    return status;
  }
  sharedata = reinterpret_cast<SharedShadowHookData*>(shared_data->shared_sh_data);
  status = DdimonInitialization(shared_data->shared_sh_data);
  if (!NT_SUCCESS(status)) {
    UtilForEachProcessor(VmpStopVM, nullptr);
    return status;
  }
  return status;
}

// Checks if the system supports virtualization
_Use_decl_annotations_ static bool VmpIsVmxAvailable() {
  PAGED_CODE();

  // See: DISCOVERING SUPPORT FOR VMX
  // If CPUID.1:ECX.VMX[bit 5]=1, then VMX operation is supported.
  int cpu_info[4] = {};
  __cpuid(cpu_info, 1);
  const CpuFeaturesEcx cpu_features = {static_cast<ULONG_PTR>(cpu_info[2])};
  if (!cpu_features.fields.vmx) {
    HYPERPLATFORM_LOG_ERROR("VMX features are not supported.");
    return false;
  }

  // See: BASIC VMX INFORMATION
  // The first processors to support VMX operation use the write-back type.
  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};
  if (static_cast<memory_type>(vmx_basic_msr.fields.memory_type) !=
      memory_type::kWriteBack) {
    HYPERPLATFORM_LOG_ERROR("Write-back cache type is not supported.");
    return false;
  }

  // See: ENABLING AND ENTERING VMX OPERATION
  Ia32FeatureControlMsr vmx_feature_control = {
      UtilReadMsr64(Msr::kIa32FeatureControl)};
  if (!vmx_feature_control.fields.lock) {
    HYPERPLATFORM_LOG_INFO("The lock bit is clear. Attempting to set 1.");
    const auto status = UtilForEachProcessor(VmpSetLockBitCallback, nullptr);
    if (!NT_SUCCESS(status)) {
      return false;
    }
  }
  if (!vmx_feature_control.fields.enable_vmxon) {
    HYPERPLATFORM_LOG_ERROR("VMX features are not enabled.");
    return false;
  }

  if (!EptIsEptAvailable()) {
    HYPERPLATFORM_LOG_ERROR("EPT features are not fully supported.");
    return false;
  }
  return true;
}

// Sets 1 to the lock bit of the IA32_FEATURE_CONTROL MSR
_Use_decl_annotations_ static NTSTATUS VmpSetLockBitCallback(void *context) {
  UNREFERENCED_PARAMETER(context);

  Ia32FeatureControlMsr vmx_feature_control = {
      UtilReadMsr64(Msr::kIa32FeatureControl)};
  if (vmx_feature_control.fields.lock) {
    return STATUS_SUCCESS;
  }
  vmx_feature_control.fields.lock = true;
  UtilWriteMsr64(Msr::kIa32FeatureControl, vmx_feature_control.all);
  vmx_feature_control.all = UtilReadMsr64(Msr::kIa32FeatureControl);
  if (!vmx_feature_control.fields.lock) {
    HYPERPLATFORM_LOG_ERROR("The lock bit is still clear.");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }
  return STATUS_SUCCESS;
}

// Initialize shared processor data
// 初始化共享數據 
// 1. 初始化MSR?圖
// 2. 初始化Hook data數組
_Use_decl_annotations_ static SharedProcessorData *VmpInitializeSharedData() 
{
  PAGED_CODE();

  //分配非分?內存 shared_data 管理hook數據
  const auto shared_data = reinterpret_cast<SharedProcessorData *>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(SharedProcessorData),
                            kHyperPlatformCommonPoolTag));
  if (!shared_data) {
    return nullptr;
  }

  RtlZeroMemory(shared_data, sizeof(SharedProcessorData));
  HYPERPLATFORM_LOG_DEBUG("SharedData=        %p", shared_data);

  // Set up the MSR bitmap

  //自定義MSR位圖
  const auto msr_bitmap = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE,
                                                kHyperPlatformCommonPoolTag);
  if (!msr_bitmap) {
    ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(msr_bitmap, PAGE_SIZE);

  //hook msr
  shared_data->msr_bitmap = msr_bitmap;

  // Checks MSRs causing #GP and should not cause VM-exit from 0 to 0xfff.
  //檢測?得的MSR會否發生#GP異常
  bool unsafe_msr_map[0x1000] = {};
  for (auto msr = 0ul; msr < RTL_NUMBER_OF(unsafe_msr_map); ++msr) {
    __try {
      UtilReadMsr(static_cast<Msr>(msr));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      unsafe_msr_map[msr] = true;
    }
  }

  // Activate VM-exit for RDMSR against all MSRs
  //bitmap 高低位
  const auto bitmap_read_low = reinterpret_cast<UCHAR *>(msr_bitmap);
  const auto bitmap_read_high = bitmap_read_low + 1024;	//加一?大小

  //用0xFF初始化
  RtlFillMemory(bitmap_read_low, 1024, 0xff);   // read        0 -     1fff
  RtlFillMemory(bitmap_read_high, 1024, 0xff);  // read c0000000 - c0001fff

  // But ignore IA32_MPERF (000000e7) and IA32_APERF (000000e8)
  // 初始化位圖
  RTL_BITMAP bitmap_read_low_header = {};
  RtlInitializeBitMap(&bitmap_read_low_header, reinterpret_cast<PULONG>(bitmap_read_low), 1024 * 8);
  RtlClearBits(&bitmap_read_low_header, 0xe7, 2);

  // Also ignore the unsage MSRs
  for (auto msr = 0ul; msr < RTL_NUMBER_OF(unsafe_msr_map); ++msr) {
    const auto ignore = unsafe_msr_map[msr];
    if (ignore) {
      RtlClearBits(&bitmap_read_low_header, msr, 1);
    }
  }

  // But ignore IA32_GS_BASE (c0000101) and IA32_KERNEL_GS_BASE (c0000102)
  RTL_BITMAP bitmap_read_high_header = {};
  RtlInitializeBitMap(&bitmap_read_high_header,
                      reinterpret_cast<PULONG>(bitmap_read_high), 1024 * 8);
  RtlClearBits(&bitmap_read_high_header, 0x101, 2);

  // Set up shared shadow hook data
  // 共享勾子數組
  shared_data->shared_sh_data = ShAllocateSharedShaowHookData();
  if (!shared_data->shared_sh_data) {
    ExFreePoolWithTag(msr_bitmap, kHyperPlatformCommonPoolTag);
    ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  return shared_data;
}

// Virtualize the current processor
_Use_decl_annotations_ static NTSTATUS VmpStartVM(void *context) 
{
  HYPERPLATFORM_LOG_INFO("Initializing VMX for the processor %d.",
                         KeGetCurrentProcessorNumberEx(nullptr));

  // 對於當前CPU
  // 1. 分配ProcessorData
  // 2. ProcessorData->ept_data << 構建EPT頁表
  // 3. ProcessorData->sh_data  << 分配及初始化ShadowHookData 填充勾子詳細資料
  // 4. 分配vmm用的棧
  // 5. 從分配到的地址,加上大小 = 棧?域地址 (因為棧是向下發展)
  // 6. 壓入ProcessorData指針
  // 7. 再壓入MAXULONG_PTR
  // 8. 以後就是可用的真正棧基址及空間
  // 9. Processor_data->shared_data << shared_data 參數上下文
  //10. 分配VMX-Region 及 VMCS, 它們的維?結構同一?->?而初始化填充vmcs各?域-> 如?置VMEXIT回?函數 -> 其中函數VmmVmExitHandler為核心, 分發exit原因
  //11. 啟動-> vmcs?置後 -> ?用匯編VMLAUNCH指令, 啟動VM
  const auto ok = AsmInitializeVm(VmpInitializeVm, context);

  NT_ASSERT(VmpIsVmmInstalled() == ok);

  if (!ok) {
    return STATUS_UNSUCCESSFUL;
  }

  HYPERPLATFORM_LOG_INFO("Initialized successfully.");

  return STATUS_SUCCESS;
}

// Allocates structures for virtualization, initializes VMCS and virtualizes
// the current processor
// 對於當前CPU
// 1. 分配ProcessorData
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
_Use_decl_annotations_ static void VmpInitializeVm(
    ULONG_PTR guest_stack_pointer,		//啟動VM時的棧指?
	ULONG_PTR guest_instruction_pointer,//啟動VM時的RIP/EIP
    void *context						//?出SharedProcessorData上下文(包含了CPU共享數據, MSR位圖,以及內存?藏的HOOK結構等)
) {					

  //把當前CPU使用的數據 參考參數定義..
  const auto shared_data = reinterpret_cast<SharedProcessorData *>(context);
  if (!shared_data) {
    return;
  }

  // Allocate related structures
  // 保管並管理所有vmx要用的數據
  const auto processor_data = reinterpret_cast<ProcessorData *>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ProcessorData), kHyperPlatformCommonPoolTag));
  
  if (!processor_data) {
    return;
  }
  RtlZeroMemory(processor_data, sizeof(ProcessorData));

  // Set up EPT
  // 分配EPT?表,並???續的內存塊到EPT?表 映射到EPT?表(即索引一樣, 如: 索引值為10 , 則按放到10), 而每分配一?PML4 亦會向下分配其?3層 共512*512*512?
  // 從而構建EPT?表(包括?續內存, LAPIC映射內存, Pre-alloc的ept表?(?有初始化))   
  processor_data->ept_data = EptInitialization();
  if (!processor_data->ept_data) {
    goto ReturnFalse;
  }

  //?置CPU的shadow hook , 分配及初始化為0
  processor_data->sh_data = ShAllocateShadowHookData();
  if (!processor_data->sh_data) {
    goto ReturnFalse;
  }
  //分配一塊24kb , 6000字節的?續空?作為vmm的棧空? 並返回基址 (注意: 棧是往上發展, 所以棧的base是需要加上size才得出棧基址 而不是直接使用)
  const auto vmm_stack_limit = UtilAllocateContiguousMemory(KERNEL_STACK_SIZE);
  //分配vmcs?域
  const auto vmcs_region =
      reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));
  //分配vmxon?域
  const auto vmxon_region =
      reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));

  // Initialize the management structure
  processor_data->vmm_stack_limit = vmm_stack_limit;
  processor_data->vmcs_region = vmcs_region;
  processor_data->vmxon_region = vmxon_region;

  if (!vmm_stack_limit || !vmcs_region || !vmxon_region) {
    goto ReturnFalse;
  }
  RtlZeroMemory(vmm_stack_limit, KERNEL_STACK_SIZE);
  RtlZeroMemory(vmcs_region, kVmxMaxVmcsSize);
  RtlZeroMemory(vmxon_region, kVmxMaxVmcsSize);

  // Initialize stack memory for VMM like this:
  //
  // (High)
  // +------------------+  <- vmm_stack_region_base      (eg, AED37000)
  // | processor_data   |
  // +------------------+  <- vmm_stack_data             (eg, AED36FFC)
  // | MAXULONG_PTR     |
  // +------------------+  <- vmm_stack_base (initial SP)(eg, AED36FF8)
  // |                  |    v
  // | (VMM Stack)      |    v (grow)
  // |                  |    v
  // +------------------+  <- vmm_stack_limit            (eg, AED34000)
  // (Low)

  //基址+棧大小得到棧最高地址
  const auto vmm_stack_region_base = reinterpret_cast<ULONG_PTR>(vmm_stack_limit) + KERNEL_STACK_SIZE;
  //如上圖, 下面直接寫入棧空? 
  const auto vmm_stack_data = vmm_stack_region_base - sizeof(void *);
  //如上圖, 下面直接寫入棧空?
  const auto vmm_stack_base = vmm_stack_data - sizeof(void *);

  //?出log
  HYPERPLATFORM_LOG_DEBUG("VmmStackTop=       %p", vmm_stack_limit);
  HYPERPLATFORM_LOG_DEBUG("VmmStackBottom=    %p", vmm_stack_region_base);
  HYPERPLATFORM_LOG_DEBUG("VmmStackData=      %p", vmm_stack_data);
  HYPERPLATFORM_LOG_DEBUG("ProcessorData=     %p stored at %p", processor_data,vmm_stack_data);
  HYPERPLATFORM_LOG_DEBUG("VmmStackBase=      %p", vmm_stack_base);
  HYPERPLATFORM_LOG_DEBUG("GuestStackPointer= %p", guest_stack_pointer);
  HYPERPLATFORM_LOG_DEBUG("GuestInstPointer=  %p", guest_instruction_pointer);

  //如圖?置 直接寫入棧空?
  *reinterpret_cast<ULONG_PTR *>(vmm_stack_base) = MAXULONG_PTR;
  //如圖?置 直接寫入棧空?
  *reinterpret_cast<ProcessorData **>(vmm_stack_data) = processor_data;

  //CPU共享數據, 當中包含共享數據的CPU總數, 以及msr位圖, 內存?藏的HOOK
  processor_data->shared_data = shared_data;

  InterlockedIncrement(&processor_data->shared_data->reference_count);

  // Set up VMCS 

  // 初始化VMXON_REGION :
  // 1. ?置VMCS版本
  // 2. ?用匯編函數,?用VMXON
  if (!VmpEnterVmxMode(processor_data)) {
    goto ReturnFalse;
  }
  //初始化VMCS_REGION
  if (!VmpInitializeVMCS(processor_data)) {
    goto ReturnFalseWithVmxOff;
  }
  //初始化vmcs
  if (!VmpSetupVMCS(processor_data, guest_stack_pointer,
                    guest_instruction_pointer, vmm_stack_base)) {
    goto ReturnFalseWithVmxOff;
  }

  // Do virtualize the processor
  //啟動vm
  VmpLaunchVM();

// Here is not be executed with successful vmlaunch. Instead, the context
// jumps to an address specified by guest_instruction_pointer.

ReturnFalseWithVmxOff:;
  __vmx_off();

ReturnFalse:;
  VmpFreeProcessorData(processor_data);
}

// See: VMM SETUP & TEAR DOWN
//?入vmx模式, 參數為Process數據
/*
struct ProcessorData {
	SharedProcessorData* shared_data;         ///< Shared data
	void* vmm_stack_limit;                    ///< A head of VA for VMM stack
	struct VmControlStructure* vmxon_region;  ///< VA of a VMXON region
	struct VmControlStructure* vmcs_region;   ///< VA of a VMCS region
	struct EptData* ept_data;                 ///< A pointer to EPT related data
	struct ShadowHookData* sh_data;           ///< Per-processor shadow hook data
};
*/

//主要功能用於?置VMXON_REGION?域, 然後啟動CPU VMX模式
_Use_decl_annotations_ static bool VmpEnterVmxMode(ProcessorData *processor_data) {
  // Apply FIXED bits

  // 求cr0寄存器某些位應如何被修正...(哪些為0, 哪些為1) 由cpu返回, ??在MSR寄存器
  const Cr0 cr0_fixed0 = {UtilReadMsr(Msr::kIa32VmxCr0Fixed0)};	//?取cr0應?要修正為0的位
  const Cr0 cr0_fixed1 = {UtilReadMsr(Msr::kIa32VmxCr0Fixed1)}; //?取cr0應?要修正為1的位
  Cr0 cr0 = {__readcr0()};										//?取cr0寄存器
	
  cr0.all &= cr0_fixed1.all;		//?置
  cr0.all |= cr0_fixed0.all;		//?置

  __writecr0(cr0.all);				//寫入修正好的cr0

  //同上
  const Cr4 cr4_fixed0 = {UtilReadMsr(Msr::kIa32VmxCr4Fixed0)};
  const Cr4 cr4_fixed1 = {UtilReadMsr(Msr::kIa32VmxCr4Fixed1)};
  Cr4 cr4 = {__readcr4()};
  cr4.all &= cr4_fixed1.all;
  cr4.all |= cr4_fixed0.all;
  __writecr4(cr4.all);				//寫入修正好的cr4

  // Write a VMCS revision identifier
  // ?取VMCS版本?
  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};
  // 寫入VMCS版本?到VMCS
  processor_data->vmxon_region->revision_identifier = vmx_basic_msr.fields.revision_identifier;
  
  //?取對應?域的物理地址
  auto vmxon_region_pa = UtilPaFromVa(processor_data->vmxon_region);
  
  //啟動, 把VMCS寫入
  /*  根據手册:
   *  程序員VMXON時 需要自己分配一?VMXON_REGION (每一?核心(???理器)應?要有對應一份的VMX_REGION)
   *  把???域的物理地址傳入,當作參數
   */
  if (__vmx_on(&vmxon_region_pa)) {
    return false;
  }
  //?置所有EPT為無效
  UtilInveptAll();
  return true;
}

// See: VMM SETUP & TEAR DOWN
// 初始化VMCS
_Use_decl_annotations_ static bool VmpInitializeVMCS(ProcessorData *processor_data) {
  // Write a VMCS revision identifier

  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};

  //?置VMCS格式的版本?
  processor_data->vmcs_region->revision_identifier =
      vmx_basic_msr.fields.revision_identifier;

  //?取VMCS物理地址
  auto vmcs_region_pa = UtilPaFromVa(processor_data->vmcs_region);

  //解除當前VMCS的綁定
  if (__vmx_vmclear(&vmcs_region_pa)) {
    return false;
  }
  //綁定VMCS到當前CPU
  if (__vmx_vmptrld(&vmcs_region_pa)) {
    return false;
  }

  // The launch state of current VMCS is "clear"
  // VM-ENTRY時的狀態要求
  // VMLAUCH -> clear	
  // VMRESUME-> launched 
  // 返回時VMCS已綁定到當前CPU, 狀態為CLEAR

  return true;
}

// See: PREPARATION AND LAUNCHING A VIRTUAL MACHINE
_Use_decl_annotations_ static bool VmpSetupVMCS(
    const ProcessorData *processor_data, 
	ULONG_PTR guest_stack_pointer,
    ULONG_PTR guest_instruction_pointer, 
	ULONG_PTR vmm_stack_pointer) 
{
  //寫入gdtr
  Gdtr gdtr = {};
  __sgdt(&gdtr);
  
  //寫入idtr
  Idtr idtr = {};
  __sidt(&idtr);

  // See: Algorithms for Determining VMX Capabilities

  const auto use_true_msrs = Ia32VmxBasicMsr{UtilReadMsr64(Msr::kIa32VmxBasic)}.fields.vmx_capability_hint;
  
  //以下填充一大堆的vmcs結構
  VmxVmEntryControls vm_entryctl_requested = {};
  //是否支持64位
  vm_entryctl_requested.fields.ia32e_mode_guest = IsX64();

  /* VMCS結構:
  *  1. Guest-state area:						//客戶機狀態域(如vmware) , ?入VMM時保存 ??VMM時恢復
		 Cr0, Cr3, Cr4
		 Dr7
		 Rsp, Rip 或對應的32位寄存器
		 所有段?擇子(包括16位?擇子?,段基址,?問權限,段大小)
		 GDTR,LDTR
		 以下MSR:
			 IA32_DEBUGCTL
			 IA32_SYSENTER_CS
			 IA32_SYSENTER_ESP & EIP
			 IA32_PERF_GLOBAL_CTRL
			 IA32_PAT
			 IA32_EFER
		SMBASE寄存器	

		Activity State(32bit)				//CPU活動狀態		
			0: Active						//活動中
			1: HLT							//正在執行HLT指令
			2: ShutDown						//由於3次??,導致?機			
			3: Wait-for-SIPI					//等待主?擬CPU,發送啟動Startup-IPI

		Interruptibility State(32bit)		//可中斷性狀態
			bit[0]: Blocking by STI			//表示STI屏蔽目前生效中			
			bit[1]: Blocking by mov SS		//表示MOV SS屏蔽目前生效中
			bit[2]: Blocking by SMI			//表示SMI屏蔽目前生效中
			bit[3]: Blocking by NMI			//表示NMI屏蔽目前生效中
			bit[31:4]: 0					//保留位, 非零會??

		Pending debug Exceptions(64/32bit)	
			bit[3:0]:  B3-B0					// 每一位表示對應的斷?狀態, DR7?有?置為會陷入VMM狀態
			bit[11:4]: 保留位				// 清零, 非零則VM entry失敗
			bit[12]:   enabled bp			// 表示最小有一?或多?數據斷?或I/O斷? 斷下 並且他已在DR7激活
			bit[14]:   bs					// 表示???異常會?發單步異常
			bit[15]:   保留位				// 清零, 非零則VM entry失敗
			bit[16]:   RTM					// 表示??事件發生在RTM?域
			bit[63:17]: 保留位				// 清零, 非零則VM entry失敗

		VMCS Link Pointer(64bit)			// 如果VMCS Shadow = 1時生效, 那?寫vmcs則在??VMCS中?寫, 否則在原有VMCS?寫(可利用?)
											// 不用時全?置為1

		vmx-preemption timer value(32bit)			// activate VMX-preemption timer = 1	 生效
													// ?置搶占式?時器的值

		Page-directory-pointer-table entry(64bit)	// Enable EPT = 1 時生效 
													// PDPTE?似於X86 ?表?

		Guest Interrupt status(16bit)				// virtual-interrupt delivery = 1時生效
			Request virtual interrupt				// 位8位, 
			Servcing virtual interrupt				// 高8位

		PML Index(16bit)							// Enable PML = 1   時生效 , PML表索引 / PML address VM-exec. 基址 ,  索引範圍為0~511 , 
													// 以上生效時, 同時?置EPTP[6]?置為1, 如??位為1 則:把所有?問當成寫入,並?置dirty bit
													// 對應?用於?置曾被?問標?(bit[8], ?問時?置) 及 dirty bit (bit[9], 寫入時?置)
													// 保存EPT PML4物理地址(4字節對?) ?似?目?
													// Ia32VmxEptVpidCapMsr 可以知道是否支持PML

  * 2. Host-state area							//宿主機狀態域(物理機器),  ??VMM時保存 ?入VMM時恢復
		只有Guest-state area的寄存器域

  * 3. VM-execution control fields			// ??vm的?置
	3.1	Pin-based VM-execution control:		// 要查看MSR保留位如何?置
			External-Interrupt exiting		// 是否捕?外部中斷
			NMI Exiting						// 是否捕?nmi中斷
			virtual NMI						// 是否捕??擬NMI中斷
			Activate VMX-Preemption Timer	// 激活搶占式?時器
			Process posted interrupts		// 

	3.2	Processor-based VM-execution control //分為主要字段 及 次要字段	
	 3.2.1	Primary Process-based VM-exec. control(32bit):		//主要字段

			 bit[2]:  Interrupt-Window				//任意指令RFLAGS.IF = 1 以及?有屏蔽中斷則陷入VMM
			 bit[3]:  Use TSC offseting				//MSR時?寄存器相?
			 bit[7]:  HLT exiting					//執行HLT指令時 , 是否發生VMEXIT(陷入VMM)
			 bit[9]:  INVLPG exiting				//同上
			 bit[10]: MWAIT exiting					//同上
			 bit[11]: RDPMC exiting					//同上
			 bit[12]: RDTSX exitng					//同上
			 bit[15]: CR-3 loading					//寫入CR3的值,是否發生VMEXIT
			 bit[16]: CR-3 store						//?取CR3的值,是否發生VMEXIT
			 bit[19]: CR-8 loading					//同上
			 bit[20]: CR-8 loading					//同上
			 bit[21]: Use TRP shadow				//是否使用TRP?擬化/ APIC?擬化
			 bit[22]: NMI-Window exiting				//?有NMI屏蔽時, 任何指令都產生VMEXIT
			 bit[23]: MOV DR exiting				//執行mov dr 指令 是否發生VMEXIT
			 bit[24]: Unconditional I/O				//無條件I/O, 是否在執行任意I/O指令時發生VMEXIT
			 bit[25]: Use I/O bitmap				//I/O位圖 , 如使用I/O bitmap, 則忽略無條件I/O
			 bit[27]: Monitor trap flag				//是否監?單步異常
			 bit[28]: Use MSR bitmaps				//是否使用MSR寄存器位圖 來控制RDMSR及WRMSR指令
			 bit[29]: MONITOR exiting				//執行MONITOR 是否VMEXIT
			 bit[30]: PAUSE exiting					//執行PAUSE 是否VMEXIT
			 bit[31]: Activate Secondary Control	//是否使用次要字段(激活ept功能的表)

	 3.2.2	Secondary Process-based VM-exec. control(32bit): //次要字段
			 bit[0]: Virtual APIC access			//APIC?擬化相?
			 bit[1]: Enable EPT						//是否啟用EPT?表
			 bit[2]: Descriptor table exiting		//執行描述符操作時 是否產生VMEXIT
			 bit[3]: Enable RDTSCP					//執行RDTSCP 是否產生#UD
			 bit[4]: Virtualize x2APIC				//APIC?擬化相?
			 bit[5]: Enable VPID					//?擬cpu id 用於緩?對應的?性地址, 提高效率
			 bit[6]: WBINVD exiting					//WBINVD指令 是否產生VMEXIT
			 bit[7]: Unrestricted guest				//決定客戶機可以?行在非分?保?模式 或 實模式
			 bit[8]: APIC-register virtualization   //APIC?擬化相?
			 bit[9]: Virtual-interrupt delivery		//中斷?擬化 以及模疑寫入APIC的寄存器 控制中斷優先級
			 bit[10]: PAUSE-loop exiting				//
			 bit[11]: RDRAND exiting				//執行RDRAND  是否產生VMEXIT
			 bit[12]: Enable INVPCID				//執行INVPCID 是否產生#UD異常
			 bit[13]: Enable VM function			//是否啟動VMFUNC
			 bit[14]: VMCS Shadowing				//VMREAD/VMWRITE ?問影子VMCS
			 bit[16]: RDSEED exiting				//RDSEED 是否產生VMEXIT
			 bit[17]: Enable PML					//是否啟用Page-modification log, ?問內存時?置dirty bit
			 bit[18]: EPT-violation (#VE)			//?問的?擬物理地址 ?有在EPT中找到(一?始只有?續的內存塊存放到EPT?表)
			 bit[20]: Enable XSAVES/SRSTORS			//XSAVES/XRSTORS 是否產生#UD異常
			 bit[25]: Use TSC scaling				//執行RDTSC/RDTSCR/RDMSR指令, 是否返回被修改的值
	3.3 Exception Bitmap(32bit)							//異常位圖, 異常發生時->在32bit?出1位, 如??位的值是1, 異常則產生VMEXIT, 否則正常地由IDT?理
	3.6 VM-Function Controls(64bit)					    //次要字段:Enable VM function = 1 , 以及?置功能?時使用(除功能?外其他置0)
	3.7 I/O Bitmap Address(64bit physical address) A/B  //use I/O bitmaps  = 1 時使用
			A包含: 0000~07fff 
			B包含: 8000~fffff
	3.8 Time-stamp Counter Offset and Multipler	(64bit)	//跟時?有?係
	3.9 Guest/Host masks CR0/CR4						//寫入CR0/CR4 的mask ?寫入?擁有?寫??寄存器的權
	3.10 read shadow for CR0/CR4(32/64bit)				//?取cr0 或cr3,?取的時侯,返回對應的read shadow中的值
	3.11 CR3-Target controls(32/64bit)					//有4?cr3-target values 以及 1?cr3-target count
														//CR3-count = N, 等如只考?首N?CR3 是否一樣, 如果一樣,則陷入VMM
														//CR3-count = 0, 則寫入CR3時無條件發生VMEXIT, 陷入VMM
  3.12 Control for APIC Virtualization
		物理上:
		  - LAPIC如果在xAPIC模式, 則可以透?內存映射?問LAPIC寄存器, 其物理地址在IA32_APIC_BASE MSR
		  - LAPIC如果在x2APIC模式, 則可以透?RDMSR或WRMSR?寫LAPIC寄存器
		  - 64位模式, 可以使用MOV CR8, ?問TPR
		?擬上:
			APIC-access Address(64bits)					//如virtualize APIC accesses = 1 時生效 , = 0 則不存在
			Virtual-APIC Address(64bits)					//如上,及Use TPR shadow = 1(只存在於?樣?置的CPU核心)
														//但地址指向4kb的物理地址,為?擬APIC? 
														//用於?擬化中斷 和?寫APIC寄存器
			TPR threshold(32bits)						//如

  3.13 MSR-Bitmap address								//Use MSR bitmap = 1, 如?寫msr時, ecx在範圍內 則產生VMEXIT 陷入VMM
		Read bitmap for low MSRs  [000000000~00001FFF]  
		Read bitmap for high MSRs [C00000000~C0001FFF]
		Write bitmap for low MSRs [000000000~00001FFF]
		Write bitmap for high MSRs[C00000000~C0001FFF] 
  3.14 Executive-VMCS Pointer							//用於SMM+SMI ???用
  3.15 EPT Pointer(64bits)								//enable EPT = 1 時有效
		bit[2:0] - Memory Type							//EPT?型: 6-回寫/0-不可緩? , 應查看MSR IA32_VMX_EPT_VPID_CAP 支持的EPT?型
		bit[5:3] - Page walk lenght						//EPT總層數
		bit[6]   - enabled accesses/dirty bit			//上面解?了, 不是所有CPU支持??功能,  應查看MSR 同上
		bit[11:7]- 保留為								//清0
		bit[N-1:12] - 4KB對?的PML4物理地址				//N代表是否物理地址寬度, 例如EAX的物理地址寬度為[7:0] 
  3.16 VPID												//?擬cpu的id,用於清除TLB緩??
  3.17 Control for PAUSE-Loop exit(32bit field)			//PLE_GAP / PLE_WINDOW
  3.17 Page-Modification Logging(64bit address)			//次要字段:Enable PML = 1 時使用
  3.18 VM Function Control								//控制?用的VM函數, 比如?用?為0 那就把0位?置為1 其他置0
  3.19 vmcs shadowing bitmap address(64bit physical addr)// VMCS Shadowing = 1, vmread / vmwrite ?問??地址 而不是原?的vmcs
  3.20 Virtualization Exception							//包含地址,??描述的地址,eptp index : 發生??的eptp索引
  3.21 xss-exiting bitmap								//enable XSAVES/XRSTORES = 1, 則使用他們時會?問??BITMAP 而不是xss寄存器
  * 5. VM-exit control fields							
				
  * 6. VM-entry control feilds

  * 7. VM-exit information fields
  */

  //根據?整MSR的
  VmxVmEntryControls vm_entryctl = {VmpAdjustControlValue(
      (use_true_msrs) ? Msr::kIa32VmxTrueEntryCtls : Msr::kIa32VmxEntryCtls,
      vm_entryctl_requested.all)};

  VmxVmExitControls vm_exitctl_requested = {};
  vm_exitctl_requested.fields.acknowledge_interrupt_on_exit = true;
  vm_exitctl_requested.fields.host_address_space_size = IsX64();
  
  VmxVmExitControls vm_exitctl = {VmpAdjustControlValue(
      (use_true_msrs) ? Msr::kIa32VmxTrueExitCtls : Msr::kIa32VmxExitCtls,
      vm_exitctl_requested.all)};

  VmxPinBasedControls vm_pinctl_requested = {};

  VmxPinBasedControls vm_pinctl = {
      VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls
                                            : Msr::kIa32VmxPinbasedCtls,
                            vm_pinctl_requested.all)};

  //第一層Processor-based vm-Execution字段的自定義?置
  VmxProcessorBasedControls vm_procctl_requested = {};
  vm_procctl_requested.fields.invlpg_exiting = false;	 //?用陷入INVLPG陷入VMM(INVLPG XXX ?置包含了xxx的TLB?的?面?置為無效時?用)
  vm_procctl_requested.fields.rdtsc_exiting = false;	 //?取tsc寄存器時陷入vmm
  vm_procctl_requested.fields.cr3_load_exiting = true;	 //寫入cr3寄存器時陷入vmm
  vm_procctl_requested.fields.cr3_store_exiting = true;
  vm_procctl_requested.fields.cr8_load_exiting = false;  //寫入cr8寄存器時陷入vmm NB: very frequent
  vm_procctl_requested.fields.mov_dr_exiting = true;	 //寫入drx寄存器時陷入VMM
  vm_procctl_requested.fields.use_msr_bitmaps = true;	 //使用MSR位圖
  vm_procctl_requested.fields.activate_secondary_control = true;

  //?置第一層Processor-based vm-Execution字段, 把上面的?置存放好
  VmxProcessorBasedControls vm_procctl = {
      VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueProcBasedCtls
                                            : Msr::kIa32VmxProcBasedCtls,
                            vm_procctl_requested.all)};

  //第二層Processor-based vm-Execution字段的自定義?置
  VmxSecondaryProcessorBasedControls vm_procctl2_requested = {};
  vm_procctl2_requested.fields.enable_ept = true;	  //啟用ept
  vm_procctl2_requested.fields.enable_rdtscp = true;  //Required for Win10
  vm_procctl2_requested.fields.descriptor_table_exiting = true; //報行段?擇子時陷入vmm

  // required for Win10 , 如果??位為0 , 引發#UD異常
  vm_procctl2_requested.fields.enable_xsaves_xstors = true;
  // ?置第二層Processor-based vm-Execution字段
  VmxSecondaryProcessorBasedControls vm_procctl2 = {VmpAdjustControlValue(Msr::kIa32VmxProcBasedCtls2, vm_procctl2_requested.all)};

  // Set up CR0 and CR4 bitmaps
  // - Where a bit is     masked, the shadow bit appears
  // - Where a bit is not masked, the actual bit appears
  // VM-exit occurs when a guest modifies any of those fields
  Cr0 cr0_mask = {};
  Cr4 cr4_mask = {};

  // See: PDPTE Registers
  // If PAE paging would be in use following an execution of MOV to CR0 or MOV
  // to CR4 (see Section 4.1.1) and the instruction is modifying any of CR0.CD,
  // CR0.NW, CR0.PG, CR4.PAE, CR4.PGE, CR4.PSE, or CR4.SMEP; then the PDPTEs are
  // loaded from the address in CR3.

  // 是否PAE模式, 如果是PAE模式 則?置以下位
  if (UtilIsX86Pae()) {
    cr0_mask.fields.pg = true;
    cr0_mask.fields.cd = true;
    cr0_mask.fields.nw = true;
    cr4_mask.fields.pae = true;
    cr4_mask.fields.pge = true;
    cr4_mask.fields.pse = true;
    cr4_mask.fields.smep = true;
  }
  //移位只#BP異常才陷入
  const auto exception_bitmap =
      1 << InterruptionVector::kBreakpointException |
      1 << InterruptionVector::kGeneralProtectionException |
      1 << InterruptionVector::kPageFaultException |
	  1 << InterruptionVector::kTrapFlags |
      0;

  // clang-format off
  /* 16-Bit Control Field */

  /* 16-Bit Guest-State Fields */
  /*保存所有段?擇子*/
  auto error = VmxStatus::kOk;
  error |= UtilVmWrite(VmcsField::kGuestEsSelector, AsmReadES());
  error |= UtilVmWrite(VmcsField::kGuestCsSelector, AsmReadCS());
  error |= UtilVmWrite(VmcsField::kGuestSsSelector, AsmReadSS());
  error |= UtilVmWrite(VmcsField::kGuestDsSelector, AsmReadDS());
  error |= UtilVmWrite(VmcsField::kGuestFsSelector, AsmReadFS());
  error |= UtilVmWrite(VmcsField::kGuestGsSelector, AsmReadGS());
  error |= UtilVmWrite(VmcsField::kGuestLdtrSelector, AsmReadLDTR());
  error |= UtilVmWrite(VmcsField::kGuestTrSelector, AsmReadTR());

  /* 16-Bit Host-State Fields */
  // RPL and TI have to be 0
  /*保存所有段選擇子 但RPL / TI位置0 (未知原因)*/ 
  error |= UtilVmWrite(VmcsField::kHostEsSelector, AsmReadES() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostCsSelector, AsmReadCS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostSsSelector, AsmReadSS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostDsSelector, AsmReadDS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostFsSelector, AsmReadFS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostGsSelector, AsmReadGS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostTrSelector, AsmReadTR() & 0xf8);

  /* 64-Bit Control Fields */
  /* 自定義MSR + 自定義EPT */
  error |= UtilVmWrite64(VmcsField::kIoBitmapA, 0);
  error |= UtilVmWrite64(VmcsField::kIoBitmapB, 0);	
  error |= UtilVmWrite64(VmcsField::kMsrBitmap, UtilPaFromVa(processor_data->shared_data->msr_bitmap));	//有使用自己一套msr
  error |= UtilVmWrite64(VmcsField::kEptPointer, EptGetEptPointer(processor_data->ept_data));			//使用自己ept(??是剛剛初始化即?續的內存的ept)

  /* 64-Bit Guest-State Fields */
  error |= UtilVmWrite64(VmcsField::kVmcsLinkPointer, MAXULONG64);//不使用影子VMCS
  error |= UtilVmWrite64(VmcsField::kGuestIa32Debugctl, UtilReadMsr64(Msr::kIa32Debugctl));
  if (UtilIsX86Pae()) {
    UtilLoadPdptes(__readcr3());
  }

  /* 32-Bit Control Fields */

  error |= UtilVmWrite(VmcsField::kPinBasedVmExecControl, vm_pinctl.all);		//使用??值
  error |= UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);		//主要字段, 包含自定義?定
  error |= UtilVmWrite(VmcsField::kExceptionBitmap, exception_bitmap);			//自己?理異唷
  error |= UtilVmWrite(VmcsField::kPageFaultErrorCodeMask, 0);					
  error |= UtilVmWrite(VmcsField::kPageFaultErrorCodeMatch, 0);					
  error |= UtilVmWrite(VmcsField::kCr3TargetCount, 0);							//**所有cr3都要捕?**
  error |= UtilVmWrite(VmcsField::kVmExitControls, vm_exitctl.all);				//EXIT CONTROL自定義了向應中斷
  error |= UtilVmWrite(VmcsField::kVmExitMsrStoreCount, 0);
  error |= UtilVmWrite(VmcsField::kVmExitMsrLoadCount, 0);
  error |= UtilVmWrite(VmcsField::kVmEntryControls, vm_entryctl.all);			//返回時做的事, ??值
  error |= UtilVmWrite(VmcsField::kVmEntryMsrLoadCount, 0);
  error |= UtilVmWrite(VmcsField::kVmEntryIntrInfoField, 0);
  error |= UtilVmWrite(VmcsField::kSecondaryVmExecControl, vm_procctl2.all);	//?置次要字段

  /* 32-Bit Guest-State Fields */
  /* 初始化客戶的段選擇子的32位的大小,權限 */
  error |= UtilVmWrite(VmcsField::kGuestEsLimit, GetSegmentLimit(AsmReadES()));	
  error |= UtilVmWrite(VmcsField::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
  error |= UtilVmWrite(VmcsField::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
  error |= UtilVmWrite(VmcsField::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
  error |= UtilVmWrite(VmcsField::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
  error |= UtilVmWrite(VmcsField::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
  error |= UtilVmWrite(VmcsField::kGuestTrLimit, GetSegmentLimit(AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kGuestGdtrLimit, gdtr.limit);
  error |= UtilVmWrite(VmcsField::kGuestIdtrLimit, idtr.limit);
  error |= UtilVmWrite(VmcsField::kGuestEsArBytes, VmpGetSegmentAccessRight(AsmReadES()));
  error |= UtilVmWrite(VmcsField::kGuestCsArBytes, VmpGetSegmentAccessRight(AsmReadCS()));
  error |= UtilVmWrite(VmcsField::kGuestSsArBytes, VmpGetSegmentAccessRight(AsmReadSS()));
  error |= UtilVmWrite(VmcsField::kGuestDsArBytes, VmpGetSegmentAccessRight(AsmReadDS()));
  error |= UtilVmWrite(VmcsField::kGuestFsArBytes, VmpGetSegmentAccessRight(AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kGuestGsArBytes, VmpGetSegmentAccessRight(AsmReadGS()));
  error |= UtilVmWrite(VmcsField::kGuestLdtrArBytes, VmpGetSegmentAccessRight(AsmReadLDTR()));
  error |= UtilVmWrite(VmcsField::kGuestTrArBytes, VmpGetSegmentAccessRight(AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kGuestInterruptibilityInfo, 0);
  error |= UtilVmWrite(VmcsField::kGuestActivityState, 0);
  error |= UtilVmWrite(VmcsField::kGuestSysenterCs, UtilReadMsr(Msr::kIa32SysenterCs));	   //代碼段 XP下為0
  
  /* 32-Bit Host-State Field */
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterCs, UtilReadMsr(Msr::kIa32SysenterCs)); //同上

  /* Natural-Width Control Fields */
  error |= UtilVmWrite(VmcsField::kCr0GuestHostMask, cr0_mask.all);	//?置客戶機的CR0 MASK 為0, 即?有?寫權
  error |= UtilVmWrite(VmcsField::kCr4GuestHostMask, cr4_mask.all); //同上
  error |= UtilVmWrite(VmcsField::kCr0ReadShadow, __readcr0());		//當前CR0
  error |= UtilVmWrite(VmcsField::kCr4ReadShadow, __readcr4());		//當前CR4

  /* Natural-Width Guest-State Fields */
  //保存cr0 , cr3 , cr4
  error |= UtilVmWrite(VmcsField::kGuestCr0, __readcr0());			//?入客戶CR0
  error |= UtilVmWrite(VmcsField::kGuestCr3, __readcr3());			//?入客戶CR3
  error |= UtilVmWrite(VmcsField::kGuestCr4, __readcr4());			//?入客戶CR4
#if defined(_AMD64_)												//以下都是64位數值
  //保存客戶機段?擇子的基址
  error |= UtilVmWrite(VmcsField::kGuestEsBase, 0);					
  error |= UtilVmWrite(VmcsField::kGuestCsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestSsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestDsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestFsBase, UtilReadMsr(Msr::kIa32FsBase));
  error |= UtilVmWrite(VmcsField::kGuestGsBase, UtilReadMsr(Msr::kIa32GsBase));
#else
  error |= UtilVmWrite(VmcsField::kGuestEsBase, VmpGetSegmentBase(gdtr.base, AsmReadES()));
  error |= UtilVmWrite(VmcsField::kGuestCsBase, VmpGetSegmentBase(gdtr.base, AsmReadCS()));
  error |= UtilVmWrite(VmcsField::kGuestSsBase, VmpGetSegmentBase(gdtr.base, AsmReadSS()));
  error |= UtilVmWrite(VmcsField::kGuestDsBase, VmpGetSegmentBase(gdtr.base, AsmReadDS()));
  error |= UtilVmWrite(VmcsField::kGuestFsBase, VmpGetSegmentBase(gdtr.base, AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kGuestGsBase, VmpGetSegmentBase(gdtr.base, AsmReadGS()));
#endif

  //以下 保存客戶機所有上下文 用於VMENTRY時恢復
  error |= UtilVmWrite(VmcsField::kGuestLdtrBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
  error |= UtilVmWrite(VmcsField::kGuestTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kGuestGdtrBase, gdtr.base);				//寫入GDT基址
  error |= UtilVmWrite(VmcsField::kGuestIdtrBase, idtr.base);				//寫入IDT基址
  error |= UtilVmWrite(VmcsField::kGuestDr7, __readdr(7));					//寫入當前CPU DR7寄存器
  error |= UtilVmWrite(VmcsField::kGuestRsp, guest_stack_pointer);			//寫入客戶機?入VMX前的rsp
  error |= UtilVmWrite(VmcsField::kGuestRip, guest_instruction_pointer);	//寫入客戶機?入VMX前的rip
  error |= UtilVmWrite(VmcsField::kGuestRflags, __readeflags());			//寫入客戶機的RLAGS
  error |= UtilVmWrite(VmcsField::kGuestSysenterEsp, UtilReadMsr(Msr::kIa32SysenterEsp));//客戶機的系統?用ESP 及EIP	
  error |= UtilVmWrite(VmcsField::kGuestSysenterEip, UtilReadMsr(Msr::kIa32SysenterEip));

  /* Natural-Width Host-State Fields */
 
  error |= UtilVmWrite(VmcsField::kHostCr0, __readcr0());		//CR0
  error |= UtilVmWrite(VmcsField::kHostCr3, __readcr3());		//CR3 
  error |= UtilVmWrite(VmcsField::kHostCr4, __readcr4());		//CR4
#if defined(_AMD64_)
  error |= UtilVmWrite(VmcsField::kHostFsBase, UtilReadMsr(Msr::kIa32FsBase));
  error |= UtilVmWrite(VmcsField::kHostGsBase, UtilReadMsr(Msr::kIa32GsBase));
#else
  error |= UtilVmWrite(VmcsField::kHostFsBase, VmpGetSegmentBase(gdtr.base, AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kHostGsBase, VmpGetSegmentBase(gdtr.base, AsmReadGS()));
#endif
  error |= UtilVmWrite(VmcsField::kHostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kHostGdtrBase, gdtr.base);
  error |= UtilVmWrite(VmcsField::kHostIdtrBase, idtr.base);
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterEsp, UtilReadMsr(Msr::kIa32SysenterEsp));
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterEip, UtilReadMsr(Msr::kIa32SysenterEip));
  //給定的棧空?
  error |= UtilVmWrite(VmcsField::kHostRsp, vmm_stack_pointer);
  //?置VMEXIT回?函數(匯編實現)
  error |= UtilVmWrite(VmcsField::kHostRip, reinterpret_cast<ULONG_PTR>(AsmVmmEntryPoint));
  // clang-format on

  const auto vmx_status = static_cast<VmxStatus>(error);
  return vmx_status == VmxStatus::kOk;
}

// Executes vmlaunch
/*_Use_decl_annotations_*/ static void VmpLaunchVM() {
  auto error_code = UtilVmRead(VmcsField::kVmInstructionError);
  if (error_code) {
    HYPERPLATFORM_LOG_WARN("VM_INSTRUCTION_ERROR = %d", error_code);
  }
  HYPERPLATFORM_COMMON_DBG_BREAK();
  auto vmx_status = static_cast<VmxStatus>(__vmx_vmlaunch());

  // Here is not be executed with successful vmlaunch. Instead, the context
  // jumps to an address specified by GUEST_RIP.
  if (vmx_status == VmxStatus::kErrorWithStatus) {
    error_code = UtilVmRead(VmcsField::kVmInstructionError);
    HYPERPLATFORM_LOG_ERROR("VM_INSTRUCTION_ERROR = %d", error_code);
  }
  HYPERPLATFORM_COMMON_DBG_BREAK();
}

// Returns access right of the segment specified by the SegmentSelector for VMX
_Use_decl_annotations_ static ULONG VmpGetSegmentAccessRight(
    USHORT segment_selector) {
  VmxRegmentDescriptorAccessRight access_right = {};
  const SegmentSelector ss = {segment_selector};
  if (segment_selector) {
    auto native_access_right = AsmLoadAccessRightsByte(ss.all);
    native_access_right >>= 8;
    access_right.all = static_cast<ULONG>(native_access_right);
    access_right.fields.reserved1 = 0;
    access_right.fields.reserved2 = 0;
    access_right.fields.unusable = false;
  } else {
    access_right.fields.unusable = true;
  }
  return access_right.all;
}

// Returns a base address of the segment specified by SegmentSelector
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBase(
    ULONG_PTR gdt_base, USHORT segment_selector) {
  const SegmentSelector ss = {segment_selector};
  if (!ss.all) {
    return 0;
  }

  if (ss.fields.ti) {
    const auto local_segment_descriptor =
        VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
    const auto ldt_base =
        VmpGetSegmentBaseByDescriptor(local_segment_descriptor);
    const auto segment_descriptor =
        VmpGetSegmentDescriptor(ldt_base, segment_selector);
    return VmpGetSegmentBaseByDescriptor(segment_descriptor);
  } else {
    const auto segment_descriptor =
        VmpGetSegmentDescriptor(gdt_base, segment_selector);
    return VmpGetSegmentBaseByDescriptor(segment_descriptor);
  }
}

// Returns the segment descriptor corresponds to the SegmentSelector
_Use_decl_annotations_ static SegmentDesctiptor *VmpGetSegmentDescriptor(
    ULONG_PTR descriptor_table_base, USHORT segment_selector) {
  const SegmentSelector ss = {segment_selector};
  return reinterpret_cast<SegmentDesctiptor *>(
      descriptor_table_base + ss.fields.index * sizeof(SegmentDesctiptor));
}

// Returns a base address of segment_descriptor
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBaseByDescriptor(
    const SegmentDesctiptor *segment_descriptor) {
  // Caluculate a 32bit base address
  const auto base_high = segment_descriptor->fields.base_high << (6 * 4);
  const auto base_middle = segment_descriptor->fields.base_mid << (4 * 4);
  const auto base_low = segment_descriptor->fields.base_low;
  ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
  // Get upper 32bit of the base address if needed
  if (IsX64() && !segment_descriptor->fields.system) {
    auto desc64 =
        reinterpret_cast<const SegmentDesctiptorX64 *>(segment_descriptor);
    ULONG64 base_upper32 = desc64->base_upper32;
    base |= (base_upper32 << 32);
  }
  return base;
}

// Adjust the requested control value with consulting a value of related MSR
_Use_decl_annotations_ static ULONG VmpAdjustControlValue(
    Msr msr, ULONG requested_value) {
  LARGE_INTEGER msr_value = {};

  //?取當野MSR的值
  msr_value.QuadPart = UtilReadMsr64(msr);
  //要修正的值
  auto adjusted_value = requested_value;

  // bit == 0 in high word ==> must be zero 不肯定..
  adjusted_value &= msr_value.HighPart;
  // bit == 1 in low word  ==> must be one
  adjusted_value |= msr_value.LowPart;
  return adjusted_value;
}

// Terminates VM
_Use_decl_annotations_ void VmTermination() {
  PAGED_CODE();
  // Create a thread dedicated to de-virtualizing processors. For some reasons,
  // de-virtualizing processors from this thread makes the system stop
  // processing all timer related events and functioning properly.
  HANDLE thread_handle = nullptr;
  auto status =
      PsCreateSystemThread(&thread_handle, GENERIC_ALL, nullptr, nullptr,
                           nullptr, VmpVmxOffThreadRoutine, nullptr);
  if (NT_SUCCESS(status)) {
    // Wait until the thread ends its work.
    status = ZwWaitForSingleObject(thread_handle, FALSE, nullptr);
    status = ZwClose(thread_handle);
  } else {
    HYPERPLATFORM_COMMON_DBG_BREAK();
  }
  NT_ASSERT(!VmpIsVmmInstalled());
}

// De-virtualizing all processors
_Use_decl_annotations_ static void VmpVmxOffThreadRoutine(void *start_context) {
  UNREFERENCED_PARAMETER(start_context);
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("Uninstalling VMM.");
  DdimonTermination();
  auto status = UtilForEachProcessor(VmpStopVM, nullptr);
  if (NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_INFO("The VMM has been uninstalled.");
  } else {
    HYPERPLATFORM_LOG_WARN("The VMM has not been uninstalled (%08x).", status);
  }
  PsTerminateSystemThread(status);
}

// Stops virtualization through a hypercall and frees all related memory
_Use_decl_annotations_ static NTSTATUS VmpStopVM(void *context) {
  UNREFERENCED_PARAMETER(context);

  HYPERPLATFORM_LOG_INFO("Terminating VMX for the processor %d.",
                         KeGetCurrentProcessorNumberEx(nullptr));

  // Stop virtualization and get an address of the management structure
  ProcessorData *processor_data = nullptr;
  auto status = UtilVmCall(HypercallNumber::kTerminateVmm, &processor_data);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  VmpFreeProcessorData(processor_data);
  return STATUS_SUCCESS;
}

// Frees all related memory
_Use_decl_annotations_ static void VmpFreeProcessorData(
    ProcessorData *processor_data) {
  if (!processor_data) {
    return;
  }
  if (processor_data->vmm_stack_limit) {
    UtilFreeContiguousMemory(processor_data->vmm_stack_limit);
  }
  if (processor_data->vmcs_region) {
    ExFreePoolWithTag(processor_data->vmcs_region, kHyperPlatformCommonPoolTag);
  }
  if (processor_data->vmxon_region) {
    ExFreePoolWithTag(processor_data->vmxon_region,
                      kHyperPlatformCommonPoolTag);
  }
  if (processor_data->sh_data) {
    ShFreeShadowHookData(processor_data->sh_data);
  }
  if (processor_data->ept_data) {
    EptTermination(processor_data->ept_data);
  }

  // Free shared data if this is the last reference
  if (processor_data->shared_data &&
      InterlockedDecrement(&processor_data->shared_data->reference_count) ==
          0) {
    HYPERPLATFORM_LOG_DEBUG("Freeing shared data...");
    if (processor_data->shared_data->msr_bitmap) {
      ExFreePoolWithTag(processor_data->shared_data->msr_bitmap,
                        kHyperPlatformCommonPoolTag);
    }
    if (processor_data->shared_data->shared_sh_data) {
      ShFreeSharedShadowHookData(processor_data->shared_data->shared_sh_data);
    }
    ExFreePoolWithTag(processor_data->shared_data, kHyperPlatformCommonPoolTag);
  }

  ExFreePoolWithTag(processor_data, kHyperPlatformCommonPoolTag);
}

// Tests if the VMM is already installed using a backdoor command
/*_Use_decl_annotations_*/ static bool VmpIsVmmInstalled() {
  int cpu_info[4] = {};
  __cpuidex(cpu_info, 0, kHyperPlatformVmmBackdoorCode);
  char vendor_id[13] = {};
  RtlCopyMemory(&vendor_id[0], &cpu_info[1], 4);  // ebx
  RtlCopyMemory(&vendor_id[4], &cpu_info[3], 4);  // edx
  RtlCopyMemory(&vendor_id[8], &cpu_info[2], 4);  // ecx
  return RtlCompareMemory(vendor_id, "Pong by VMM!\0", sizeof(vendor_id)) ==
         sizeof(vendor_id);
}

}  // extern "C"
