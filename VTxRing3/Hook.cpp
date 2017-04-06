 
#include "stdafx.h"
#include "Hook.h" 
#include <dos.h>   // definitions for _disable, _enable  
#pragma intrinsic(_disable)  
#pragma intrinsic(_enable)  
#define RtlFreeMemory(pObj)			VirtualFree(pObj, 0 , MEM_RELEASE); 

typedef struct _PLATFORM_DESC 
{
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
	cs_opt_type opt_type;
	cs_opt_value opt_value;
}PLATFORMDESC, *PPLATFORMDESC;

BOOLEAN IsX64()
{
#if defined(_AMD64_)
		return TRUE;
#else
		return FALSE;
#endif
}

//----------------------------------------------------------------------------------//
EXTERN_C
	SIZE_T
	GetInstructionSize(
		void* address
	)
{
	// Disassemble at most 15 bytes to get an instruction size
	csh handle = {};
	const auto mode = IsX64() ? CS_MODE_64 : CS_MODE_32;
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
	{
		return 0;
	}

	static const auto kLongestInstSize = 15;
	cs_insn* instructions = nullptr;
	const auto count =
		cs_disasm(handle, reinterpret_cast<uint8_t*>(address), kLongestInstSize,
			reinterpret_cast<uint64_t>(address), 1, &instructions);
	if (count == 0) {
		cs_close(&handle);
		return 0;
	}

	// Get a size of the first instruction
	const auto size = instructions[0].size;
	cs_free(instructions, count);
	cs_close(&handle);
	return size;
}
//-------------------------------------------------------------------------//
// Returns code bytes for inline hooking
EXTERN_C
	TrampolineCode MakeTrampolineCode(
		void* hook_handler)
{
#if defined(_AMD64_)
		// 90               nop
		// ff2500000000     jmp     qword ptr cs:jmp_addr
		// jmp_addr:
		// 0000000000000000 dq 0
		return{
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
		return{
			0x90, 0x68, hook_handler, 0xc3,
		};
#endif
}


//------------------------------------------//
EXTERN_C
BOOLEAN SetupInlineHook_X64(
	_Inout_ PHOOKOBJ* HookObject,
	_In_ PVOID HookAddress,
	_In_ PVOID HookHandler)
{	
	int				InstSize = 0;
	BOOLEAN			ret = FALSE;
	PHOOKOBJ		pObj = NULL;
	PLATFORMDESC	desc = {};
	ULONG			oldProtect = 0; 
	TrampolineCode	trampolineCode = { 0 };

	if (!HookAddress || !HookHandler)
	{
		return FALSE;
	}
	pObj = (PHOOKOBJ)VirtualAlloc(NULL, sizeof(HOOKOBJ), MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	if (!pObj)
	{
		return FALSE;
	} 

	while (InstSize < 15)
	{
		InstSize += GetInstructionSize(HookAddress);
	} 
	if (!InstSize)
	{
		RtlFreeMemory(pObj);
		return FALSE;
	}

	pObj->JmpToOrg = VirtualAlloc(NULL, InstSize + sizeof(TrampolineCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pObj->JmpToOrg)
	{
		RtlFreeMemory(pObj);
		return FALSE;
	}
	
	trampolineCode = MakeTrampolineCode((PUCHAR)HookAddress + InstSize);
	
	RtlCopyMemory(pObj->JmpToOrg, HookAddress, InstSize);
	RtlCopyMemory((PUCHAR)pObj->JmpToOrg + InstSize, &trampolineCode, sizeof(TrampolineCode));

	VirtualProtect(HookAddress, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);

	// Set hook
	trampolineCode = MakeTrampolineCode(HookHandler);
 
//	CHAR breakpoint = 0xCC;
	RtlCopyMemory(HookAddress, &trampolineCode, InstSize);
//	RtlCopyMemory(HookAddress, &breakpoint , InstSize);

	if (InstSize > 15)
	{
		memcpy(HookAddress, (PUCHAR)0x90, InstSize - 15);
		OutputDebugString(L"Over 15 inst len \r\n");
	}

	VirtualProtect(HookAddress, 4096, oldProtect, &oldProtect);

	pObj->HookAddress = HookAddress;

	*HookObject = pObj;

	OutputDebugString(L"Finish hook \r\n");

	return ret;
} 