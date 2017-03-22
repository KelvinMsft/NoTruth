/*============================
Drvier Control Class (SCM way)
============================*/
#include "stdafx.h"
#pragma comment(lib,"advapi32.lib")
#include <winioctl.h>
#include "cDrvCtrl.h"

BOOL cDrvCtrl::GetSvcHandle(PCHAR pServiceName)
{
	m_pServiceName = pServiceName;
	m_hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == m_hSCManager)
	{
		m_dwLastError = GetLastError();
		return FALSE;
	}
	m_hService = OpenServiceA(m_hSCManager, m_pServiceName, SERVICE_ALL_ACCESS);
	if (NULL == m_hService)
	{
		CloseServiceHandle(m_hSCManager);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL cDrvCtrl::Install(PCHAR pSysPath, PCHAR pServiceName, PCHAR pDisplayName)
{
 
	BOOLEAN ret = FALSE;
	CString err;
	m_pSysPath = pSysPath;
	m_pServiceName = pServiceName;
	m_pDisplayName = pDisplayName;
Init:
	m_hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == m_hSCManager)
	{
		m_dwLastError = GetLastError();
		err.Format(L"m_hSCManager NULL ERR: %X\r\n", m_dwLastError);
		OutputDebugString(err);
		ret = FALSE;
	}

	m_hService = CreateServiceA(m_hSCManager, m_pServiceName, m_pDisplayName,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		m_pSysPath, NULL, NULL, NULL, NULL, NULL);

	if (NULL == m_hService)
	{
		if (ERROR_SERVICE_EXISTS == m_dwLastError)
		{
			m_hService = OpenServiceA(m_hSCManager, m_pServiceName, SERVICE_ALL_ACCESS);
			if (NULL == m_hService)
			{
				DeleteService(m_hService);
				goto Init;
				CloseServiceHandle(m_hSCManager);
				ret = FALSE;
			}
			ret = TRUE;
		}
		else
		{
			m_dwLastError = GetLastError();
			err.Format(L"CreateService ERR: %X\r\n", m_dwLastError);
			OutputDebugString(err);
			CloseServiceHandle(m_hSCManager);
			ret = FALSE;
		}
	}
	else
	{
		ret = TRUE;
	}
	return ret;
}

BOOL cDrvCtrl::Start()
{
	GetSvcHandle(m_pServiceName);
	if (!StartServiceA(m_hService, NULL, NULL))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL cDrvCtrl::Stop()
{
	BOOLEAN ret = TRUE;
	SERVICE_STATUS ss;
	CString str;
	GetSvcHandle(m_pServiceName);
	if (!ControlService(m_hService, SERVICE_CONTROL_STOP, &ss))
	{
		m_dwLastError = GetLastError();
		str.Format(L"Stop error: %x", m_dwLastError);
		ret = FALSE;
	}
	return ret;

}

BOOL cDrvCtrl::Remove()
{
	BOOLEAN ret = TRUE;;
	CString str;
	GetSvcHandle(m_pServiceName);
	if (!DeleteService(m_hService))
	{
		m_dwLastError = GetLastError();
		str.Format(L"Remove error: %x", m_dwLastError);
		OutputDebugString(str);
		ret = FALSE;
	}
	m_hService = NULL;
	return ret;
}

BOOL cDrvCtrl::Open(PCHAR pLinkName)//example: \\\\.\\xxoo
{
	if (m_hDriver != INVALID_HANDLE_VALUE)
		return TRUE;
	m_hDriver = CreateFileA(pLinkName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (m_hDriver != INVALID_HANDLE_VALUE)
		return TRUE;
	else
		return FALSE;
}

BOOL cDrvCtrl::IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes)
{
	DWORD dw;
	BOOL b = DeviceIoControl(m_hDriver, dwIoCode, InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);
	if (RealRetBytes)
		*RealRetBytes = dw;
	return b;
}

DWORD cDrvCtrl::CTL_CODE_GEN(DWORD lngFunction)
{
	return (FILE_DEVICE_UNKNOWN * 65536) | (FILE_ANY_ACCESS * 16384) | (lngFunction * 4) | METHOD_BUFFERED;
}