#include "Windows.h"
#include <winsvc.h>
class cDrvCtrl
{
public:
	cDrvCtrl()
	{
		m_pSysPath = NULL;
		m_pServiceName = NULL;
		m_pDisplayName = NULL;
		m_hSCManager = NULL;
		m_hService = NULL;
		m_hDriver = INVALID_HANDLE_VALUE;
	}
	~cDrvCtrl()
	{
		CloseServiceHandle(m_hService);
		CloseServiceHandle(m_hSCManager);
		CloseHandle(m_hDriver);
	}
public:
	DWORD m_dwLastError;
	PCHAR m_pSysPath;
	PWCHAR m_pServiceName;
	PCHAR m_pDisplayName;
	HANDLE m_hDriver;
	SC_HANDLE m_hSCManager;
	SC_HANDLE m_hService;
public:
	BOOL Install(PCHAR pSysPath, PCHAR pServiceName, PCHAR pDisplayName);
	BOOL Start(PCHAR pSysPath);
	BOOL Stop(PCHAR pSysPath);
	BOOL Remove(PCHAR pSysPath);
	BOOL IoControl(PCHAR SymbolicName, DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes);
private:
	DWORD CTL_CODE_GEN(DWORD lngFunction);
protected:
	//null
};