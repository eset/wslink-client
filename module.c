// -*- encoding: utf8 -*-
// 
// Copyright (c) 2021 ESET spol. s r.o.
// Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
// See LICENSE file for redistribution.

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

// https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,	 // reason for calling function
	LPVOID lpReserved )  // reserved
{
	// Perform actions based on the reason for calling.
	switch( fdwReason ) 
	{ 
		case DLL_PROCESS_ATTACH:
		 // Initialize once for each new process.
		 // Return FALSE to fail DLL load.
			break;

		case DLL_THREAD_ATTACH:
		 // Do thread-specific initialization.
			break;

		case DLL_THREAD_DETACH:
		 // Do thread-specific cleanup.
			break;

		case DLL_PROCESS_DETACH:
		 // Perform any necessary cleanup.
			break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

// https://docs.microsoft.com/en-us/windows/win32/procthread/creating-processes
__declspec(dllexport) void exp1() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	// Start the child process. 
	if( !CreateProcess( NULL,   // No module name (use command line)
		"C:\\Windows\\system32\\calc.exe",		// Command line
		NULL,		   // Process handle not inheritable
		NULL,		   // Thread handle not inheritable
		FALSE,		  // Set handle inheritance to FALSE
		0,			  // No creation flags
		NULL,		   // Use parent's environment block
		NULL,		   // Use parent's starting directory 
		&si,			// Pointer to STARTUPINFO structure
		&pi )		   // Pointer to PROCESS_INFORMATION structure
	) 
	{
		printf( "CreateProcess failed (%d).\n", GetLastError() );
		return;
	}

	// Close process and thread handles. 
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );
}
