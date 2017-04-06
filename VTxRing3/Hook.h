#include "..\VTxRing3\capstone\include\capstone.h"

#pragma pack(1)
#ifndef defined(_AMD64_)
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
#pragma pack()

typedef struct _HOOK_OBJ
{
#ifdef _WIN64 
	PVOID64				HookAddress;  
	TrampolineCode		JmpToHandler; 
	PVOID64				JmpToOrg;   
#else
	PVOID				HookAddress;
	TrampolineCode		JmpToHandler;
	PVOID				JmpToOrg;
#endif
}HOOKOBJ, *PHOOKOBJ;

EXTERN_C
BOOLEAN SetupInlineHook_X64(
	_Inout_ PHOOKOBJ* HookObject,
	_In_ PVOID HookAddress,
	_In_ PVOID HookHandler);