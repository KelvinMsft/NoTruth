
// VTxRing3Dlg.cpp : implementation file
//

#include "stdafx.h"
#include "VTxRing3.h"
#include "VTxRing3Dlg.h"
#include "afxdialogex.h"
#include "cDrvCtrl.h"
#include "IOCTL.h"	
#include "tlhelp32.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#include <winternl.h>

#pragma comment(lib,"ntdll.lib") // Need to link with ntdll.lib import library. You can find the ntdll.lib from the Windows DDK.

typedef struct _TRANSFER_IOCTL
{
	ULONG64 ProcID;
	ULONG64 HiddenType;
	ULONG64 Address;
}TRANSFERIOCTL, *PTRANSFERIOCTL;
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CVTxRing3Dlg dialog



CVTxRing3Dlg::CVTxRing3Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_VTXRING3_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CVTxRing3Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CVTxRing3Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CVTxRing3Dlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CVTxRing3Dlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_BUTTON1, &CVTxRing3Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CVTxRing3Dlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CVTxRing3Dlg message handlers

BOOL CVTxRing3Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CVTxRing3Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CVTxRing3Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CVTxRing3Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
DWORD FindProcessId(WCHAR*processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
	//	OutputDebugStringA("!!! Failed to gather information on system processes! \n");
		return(NULL);
	}

	do
	{
//		OutputDebugStringA("Checking process\n");
		if (0 == _wcsicmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}
cDrvCtrl drv;


void CVTxRing3Dlg::OnBnClickedOk()
{
	CString err;
	if (drv.Install("C:\\NoTruth.sys", "NoTruthtest3", "NoTruthtest3")) {
		if (drv.Start())
		{
			PVOID NtCreateThread = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateThread");
			PVOID NtCreateFile = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateFile");
			if (NtCreateThread)
			{
				DWORD oldProtect;
				ULONG OutBuffer, RetBytes;
				
				TRANSFERIOCTL transferData = { 0 };
				transferData.ProcID = GetCurrentProcessId();
				transferData.HiddenType = 0x0;
				VirtualProtect(NtCreateThread, sizeof(UCHAR), PAGE_EXECUTE_WRITECOPY, &oldProtect);
				transferData.Address = (ULONG64)NtCreateThread;


				VirtualProtect(NtCreateThread, sizeof(UCHAR), oldProtect, NULL);
				*(PUCHAR)transferData.Address = *(PUCHAR)transferData.Address;
				err.Format(L"[VTxRing3]ProcID: %x Address1: %X OldValue : %X \r\n", transferData.ProcID, transferData.Address, *(PUCHAR)transferData.Address);
				OutputDebugString(err);

			

				TRANSFERIOCTL transferData2 = { 0 };
				DWORD pid = (DWORD)FindProcessId(L"notepad.exe");
				transferData2.ProcID = pid;
				transferData2.HiddenType = 0x0;
				transferData2.Address = (ULONG64)NtCreateFile;			
				HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				UCHAR  value = 0;
				VirtualProtectEx(handle, (LPVOID)transferData2.Address, sizeof(value), PAGE_EXECUTE_WRITECOPY, &oldProtect);
				ReadProcessMemory(handle, (LPVOID)transferData2.Address, &value , sizeof(value),NULL);
				err.Format(L"[NOTEPAD]ProcID: %x Address1: %X oldValue : %X \r\n", transferData2.ProcID, transferData2.Address, value);
				OutputDebugString(err);	
				
				if (WriteProcessMemory(handle, (PVOID)transferData2.Address, &value , 4, NULL))
				{
					WriteProcessMemory(handle, (PVOID)transferData2.Address, &value, 4, NULL);
					WriteProcessMemory(handle, (PVOID)transferData2.Address, &value, 4, NULL);
					OutputDebugStringA("Written process memory \r\n");
				}
				else
				{
					OutputDebugStringA("written process memory error \r\n");
				}
				VirtualProtectEx(handle,(LPVOID)transferData2.Address, sizeof(UCHAR), oldProtect, NULL);
				 

				if (!pid)
				{ 
					transferData2 = { 0 };
				}  
				
				if (drv.Open("\\\\.\\NoTruth"))	
				{

					if(transferData2.Address && transferData2.ProcID)
					if (!drv.IoControl(IOCTL_HIDE, &transferData2, sizeof(TRANSFERIOCTL), &OutBuffer, sizeof(ULONG), &RetBytes))
					{
						AfxMessageBox(L"Cannot IOCTL device \r\n");
					}
					UCHAR bp   = 0xCC;
					UCHAR retv =  0x0;
					if (WriteProcessMemory(handle, (PVOID)transferData2.Address, &bp, sizeof(UCHAR), NULL))
					{
						OutputDebugStringA("Written process memory1 \r\n");
						ReadProcessMemory(handle, (PVOID)transferData2.Address, &retv, sizeof(UCHAR), NULL);
						err.Format(L"[notepad]ProcID: %x Address1: %X newValue : %X \r\n", transferData2.ProcID, transferData2.Address, *(PUCHAR)transferData2.Address);
						OutputDebugString(err);
					}
					else
					{
						//err.Format(L"Write process ERROR : %X \r\n", GetLastError());
						//OutputDebugString(err);
					}
					
					if (!drv.IoControl(IOCTL_HIDE, &transferData, sizeof(TRANSFERIOCTL), &OutBuffer, sizeof(ULONG), &RetBytes))
					{
						AfxMessageBox(L"Cannot IOCTL device \r\n");
					}
					*(PUCHAR)transferData.Address = 0xCC;
					err.Format(L"[VTxRing3]ProcID: %x Address1: %X newValue : %X \r\n", transferData.ProcID, transferData.Address, *(PUCHAR)transferData.Address);
					OutputDebugString(err);  

				
				}
				else
				{
					AfxMessageBox(L"Cannot open device \r\n");
				}

				CloseHandle(handle);
				CloseHandle(drv.m_hDriver);
			}
		}
		else 
		{	
			err.Format(L"Cannot start driver ERR 2 : %X \r\n", GetLastError());		
			AfxMessageBox(err);
		}
	}
	else 
	{ 
		if (drv.Start())
		{
			PVOID NtCreateThread = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateThread");
			PVOID NtCreateFile = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateFile");
			if (NtCreateThread)
			{
				DWORD oldProtect;
				ULONG OutBuffer, RetBytes;

				TRANSFERIOCTL transferData = { 0 };
				transferData.ProcID = GetCurrentProcessId();
				transferData.HiddenType = 0x0;
				VirtualProtect(NtCreateThread, sizeof(UCHAR), PAGE_EXECUTE_WRITECOPY, &oldProtect);
				transferData.Address = (ULONG64)NtCreateThread;
				VirtualProtect(NtCreateThread, sizeof(UCHAR), oldProtect, NULL);

				err.Format(L"ProcID: %x Address1: %X OldValue : %X \r\n", transferData.ProcID, transferData.Address, *(PULONG)transferData.Address);
				OutputDebugString(err);

				TRANSFERIOCTL transferData2 = { 0 };
				DWORD pid = (DWORD)FindProcessId(L"notepad.exe");
				transferData2.ProcID = pid;
				transferData2.HiddenType = 0x0;
				transferData2.Address = (ULONG64)NtCreateFile;

				*(PUCHAR)transferData.Address = *(PUCHAR)transferData.Address;

				ULONG  value = *(PULONG)transferData2.Address;

				HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				SIZE_T retsize;
				err.Format(L"[NOTEPAD]ProcID: %x Address1: %X newValue : %X \r\n", transferData.ProcID, transferData2.Address, *(PULONG)transferData2.Address);
				OutputDebugString(err);
				if (WriteProcessMemory(handle, (PVOID)transferData2.Address, &value, 4, NULL))
				{
					WriteProcessMemory(handle, (PVOID)transferData2.Address, &value, 4, NULL);
					WriteProcessMemory(handle, (PVOID)transferData2.Address, &value, 4, NULL);

					OutputDebugStringA("Written process memory \r\n");
				}
				else
				{
					OutputDebugStringA("written process memory error \r\n");
				}
				CloseHandle(handle);

				if (!pid)
				{
					transferData2 = { 0 };
				}
				err.Format(L"ProcID: %x Address2: %X", transferData2.ProcID, transferData2.Address);
				OutputDebugString(err);

				if (drv.Open("\\\\.\\NoTruth"))
				{

					if (transferData2.Address && transferData2.ProcID)
						if (!drv.IoControl(IOCTL_HIDE, &transferData2, sizeof(TRANSFERIOCTL), &OutBuffer, sizeof(ULONG), &RetBytes))
						{
							AfxMessageBox(L"Cannot IOCTL device \r\n");
						}
					if (!drv.IoControl(IOCTL_HIDE, &transferData, sizeof(TRANSFERIOCTL), &OutBuffer, sizeof(ULONG), &RetBytes))
					{
						AfxMessageBox(L"Cannot IOCTL device \r\n");
					}
					ULONG bp = 0xCCCCCCCC;
					ULONG retv = 0;
					if (WriteProcessMemory(handle, (PVOID)transferData2.Address, &bp, 4, NULL))
					{
						//OutputDebugStringA("Written process memory \r\n");
						ReadProcessMemory(handle, (PVOID)transferData2.Address, &retv, 4, NULL);
						err.Format(L"[notepad]ProcID: %x Address1: %X newValue : %X \r\n", transferData2.ProcID, transferData2.Address, *(PULONG)transferData2.Address);
						OutputDebugString(err);
					}
					else
					{
						OutputDebugStringA("written process memory error \r\n");
					}

					*(PUCHAR)transferData.Address = 0xCC;
					err.Format(L"[VTxRing3]ProcID: %x Address1: %X newValue : %X \r\n", transferData.ProcID, transferData.Address, *(PULONG)transferData.Address);
					OutputDebugString(err);



				}
				else
				{
					AfxMessageBox(L"Cannot open device \r\n");
				}
				CloseHandle(drv.m_hDriver);
			}
	}
		else
		{
			err.Format(L"Cannot start driver ERR 1 : %X \r\n", GetLastError());
			AfxMessageBox(err);
		}
	}
}


void CVTxRing3Dlg::OnBnClickedCancel()
{
	CDialog::OnCancel();
}


void CVTxRing3Dlg::OnBnClickedButton1()
{
	CString err;
	PVOID NtCreateThread = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateThread");
	if (NtCreateThread)
	{
		ULONG OutBuffer, RetBytes;
		TRANSFERIOCTL transferData = { 0 };
		transferData.ProcID = GetCurrentProcessId();
		transferData.HiddenType = 0x0;
		transferData.Address = (ULONG64)NtCreateThread;
		err.Format(L"ProcID: %x Address: %X", transferData.ProcID, transferData.Address);
		OutputDebugString(err);
		if (drv.Open("\\\\.\\NoTruth")) 
		{
			if (!drv.IoControl(IOCTL_HIDE, &transferData, sizeof(TRANSFERIOCTL), &OutBuffer, sizeof(ULONG), &RetBytes)) 
			{
				AfxMessageBox(L"Cannot IOCTL device \r\n");
			}
		}
		else {
			AfxMessageBox(L"Cannot open device \r\n");
		}
	}
}

void CVTxRing3Dlg::OnBnClickedButton2()
{
	// TODO: Add your control notification handler code here
	drv.Stop();
	drv.Remove();

}
