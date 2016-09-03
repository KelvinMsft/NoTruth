
// VTxRing3.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CVTxRing3App:
// See VTxRing3.cpp for the implementation of this class
//

class CVTxRing3App : public CWinApp
{
public:
	CVTxRing3App();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CVTxRing3App theApp;