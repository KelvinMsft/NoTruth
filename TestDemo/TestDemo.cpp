// TestDemo.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"

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


typedef BOOLEAN (__stdcall *pSetupInlineHook_X64)(
	_Inout_ PHOOKOBJ* HookObject,
	_In_ PVOID HookAddress,
	_In_ PVOID HookHandler);


typedef NTSTATUS(*pMyNtCreateThread)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PVOID ClientId,
	IN PCONTEXT ThreadContext,
	IN PVOID InitialTeb,
	IN BOOLEAN CreateSuspended);

typedef void(__stdcall *pUnitTest)(PVOID HookAddress, PVOID ProxyFunction);

pMyNtCreateThread g_NtCreateThread = NULL;

HOOKOBJ* g_HookObj = NULL;

//--------------------------------------------------------------------------------------------// 
template <typename T>
static T  FindOrignal(T handler, HOOKOBJ* g_HookObj)
{
	return reinterpret_cast<T>(g_HookObj->JmpToOrg);
}


//--------------------------------------------------------------------------------------------//
NTSTATUS
MyNtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PVOID ClientId,
	IN PCONTEXT ThreadContext,
	IN PVOID InitialTeb,
	IN BOOLEAN CreateSuspended)
{
	 
	OutputDebugString(L"Test my thread hook \r\n");

	const auto Original = FindOrignal(MyNtCreateThread, g_HookObj);

	const auto status = Original(
		ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		ThreadContext,
		InitialTeb,
		CreateSuspended
	);
	 
	return status;
}


//----------------------------------------------//
ULONG DumpExecptionCode(ULONG exception)
{
	printf("Hidden Exception ( code: 0x%X ) \r\n", exception); 
	return 1;
}
//----------------------------------------------//
DWORD WINAPI ExecuteThread(PVOID Param)
{
	ULONG  Hash;
	while (1)
	{
		__try {
			g_NtCreateThread(0, 0, 0, 0, 0, 0, 0, 0);
		}
		__except (DumpExecptionCode(GetExceptionCode()))
		{

		}
		Sleep(1000);
	}
	return 0;
}
//----------------------------------------------//
DWORD WINAPI CheckSumThread(PVOID Param)
{
	 
	ULONG  Hash;

	while (1)
	{
		ULONG value = 0;
		value = *(PULONG)g_NtCreateThread;
		printf("Checksum Value: %x TickCount: %I64x \r\n", value, GetTickCount());
		Sleep(1000);
	}
	return 0;
} 
//----------------------------------------------//
int main()
{
	g_NtCreateThread = (pMyNtCreateThread)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateThread");

	pUnitTest UnitTest = (pUnitTest)GetProcAddress(LoadLibrary(L"VTxRing3.dll"), "UnitTest");
	pSetupInlineHook_X64 SetupInlineHook_X64 = (pSetupInlineHook_X64)GetProcAddress(LoadLibrary(L"VTxRing3.dll"), "SetupInlineHook_X64");

	printf("g_NtCreateThread: %I64x UnitTest: %I64x SetupInlineHook_X64: %I64x ", g_NtCreateThread, UnitTest, SetupInlineHook_X64);

	if (g_NtCreateThread&&UnitTest&&SetupInlineHook_X64)
	{ 
		UnitTest(g_NtCreateThread, MyNtCreateThread);
		SetupInlineHook_X64(&g_HookObj, g_NtCreateThread, MyNtCreateThread); 

		for (int i = 0; i < 10; i++)
		{
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CheckSumThread, 0, 0, 0);
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ExecuteThread, 0, 0, 0);
		}
	}

	getchar();

    return 0;
}

