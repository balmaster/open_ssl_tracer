// tracessl.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "Config.h"


#ifdef _MANAGED
#pragma managed(push, off)
#endif

static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];

static Config * config;

// в данной библиотеке не перехватываются, но нужно сообщить об этом сервису логгера
extern "C" {
    HANDLE (WINAPI * Real_CreateFileW)(LPCWSTR a0,
                                       DWORD a1,
                                       DWORD a2,
                                       LPSECURITY_ATTRIBUTES a3,
                                       DWORD a4,
                                       DWORD a5,
                                       HANDLE a6)
        = CreateFileW;

    BOOL (WINAPI * Real_WriteFile)(HANDLE hFile,
                                   LPCVOID lpBuffer,
                                   DWORD nNumberOfBytesToWrite,
                                   LPDWORD lpNumberOfBytesWritten,
                                   LPOVERLAPPED lpOverlapped)
        = WriteFile;

    BOOL (WINAPI * Real_FlushFileBuffers)(HANDLE hFile)
        = FlushFileBuffers;

    BOOL (WINAPI * Real_CloseHandle)(HANDLE hObject)
        = CloseHandle;

    BOOL (WINAPI * Real_WaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
        = WaitNamedPipeW;

    BOOL (WINAPI * Real_SetNamedPipeHandleState)(HANDLE hNamedPipe,
                                                 LPDWORD lpMode,
                                                 LPDWORD lpMaxCollectionCount,
                                                 LPDWORD lpCollectDataTimeout)
        = SetNamedPipeHandleState;

    DWORD (WINAPI * Real_GetCurrentProcessId)(VOID)
        = GetCurrentProcessId;

    VOID (WINAPI * Real_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
        = GetSystemTimeAsFileTime;

    VOID (WINAPI * Real_InitializeCriticalSection)(LPCRITICAL_SECTION lpSection)
        = InitializeCriticalSection;

    VOID (WINAPI * Real_EnterCriticalSection)(LPCRITICAL_SECTION lpSection)
        = EnterCriticalSection;

    VOID (WINAPI * Real_LeaveCriticalSection)(LPCRITICAL_SECTION lpSection)
        = LeaveCriticalSection;
};


// перехватываем чтение и запись 
extern "C" {

int	( * real_SSL_read)(SSL *s, void *data, int len);
int	( * real_SSL_write)(SSL *s, const void *data, int len);

const char * LETTERS = "0123456789ABCDEF";
void str2Hex(const char* aSrc, char* aDst, int len)
{
	for(int i=0;i<len;i++)
	{
		aDst[2*i] = LETTERS[aSrc[i]>>4];				
		aDst[2*i+1] = LETTERS[aSrc[i] & 0x0F];				
	}
	aDst[len*2] = 0;
}

void WriteDataToStream(std::ofstream & stream,const char * data)
{
	int len=strlen(data);
	for(int i=0;i<len;i++)
	{
		unsigned char c = data[i];
		if(c==0xFD) stream<<" ";
		else if(c==0xFE) stream<<"\n\r";
		else stream << c;
	}
}

int	traced_SSL_read(SSL *s, void *data, int len)
{
	int res = real_SSL_read(s,data,len);
	if(res > 0)
	{
		char* buffer = new char[res+1];
		memcpy(buffer,data,res);
		buffer[res]=0;

		std::ostringstream o;
		o<<std::hex<<config->GetLogPath()<<"\\"<<(int)s<<"_read";
		std::ofstream f(o.str().c_str(),std::ios_base::in | std::ios_base::out | std::ios_base::app | std::ios_base::ate);
		WriteDataToStream(f,buffer);
		f.flush();
	}
	//Syelog(SYELOG_SEVERITY_DEBUG,"result %d.\n", res);
	return res;
}

int	traced_SSL_write(SSL *s, const void *data, int len)
{
	if(len>0)
	{
		char* buffer = new char[len+1];
		memcpy(buffer,data,len);
		buffer[len]=0;

		std::ostringstream o;
		o<<config->GetLogPath()<<"\\"<<std::hex<<(int)s<<"_write";
		std::ofstream f(o.str().c_str(),std::ios_base::in | std::ios_base::out | std::ios_base::app| std::ios_base::ate);
		WriteDataToStream(f,buffer);
		f.flush();
	}
	int res = real_SSL_write(s,data,len);
	//Syelog(SYELOG_SEVERITY_DEBUG,"result %d.\n", res);
	return res;
}

};


PCHAR DetRealName(PCHAR psz)
{
    PCHAR pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
           ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return psz;
}

VOID DetAttach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
	Syelog(SYELOG_SEVERITY_NOTICE,"DetAttach real %x mine %x\n", *ppbReal,pbMine);
    LONG l = DetourAttach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Attach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

VOID DetDetach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourDetach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Detach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

#define ATTACH(x,y)   DetAttach(x,y,#x)
#define DETACH(x,y)   DetDetach(x,y,#x)



LONG AttachDetours(VOID)
{
	config = new Config("tracessl.ini");	
	Syelog(SYELOG_SEVERITY_NOTICE,"module %s\n", config->GetModule().c_str());
	Syelog(SYELOG_SEVERITY_NOTICE,"log %s\n", config->GetLogPath().c_str());
	Syelog(SYELOG_SEVERITY_NOTICE,"read %x\n", config->GetSSLReadOffset());
	Syelog(SYELOG_SEVERITY_NOTICE,"write %x\n", config->GetSSLWriteOffset());

	const char * moduleName = config->GetModule().c_str();
	HMODULE	module = GetModuleHandle(moduleName);
	// load library if not loaded 
	if(module==0)
	{
		module = LoadLibrary(moduleName);
	}
	
	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	// find real SSL proc addresses
	if(module!=NULL)
	{
		Syelog(SYELOG_SEVERITY_NOTICE,"Main module base %x\n", module);
		
		real_SSL_read = (int (__cdecl *)(SSL *,void *,int))((unsigned long)module + config->GetSSLReadOffset());
		real_SSL_write = (int (__cdecl *)(SSL *,const void *,int))((unsigned long)module + config->GetSSLWriteOffset());

	}	

	ATTACH(&(PVOID&)real_SSL_read, traced_SSL_read);
    ATTACH(&(PVOID&)real_SSL_write, traced_SSL_write);
    return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	DETACH(&(PVOID&)real_SSL_read, traced_SSL_read);
    DETACH(&(PVOID&)real_SSL_write, traced_SSL_write);

	delete config;

    return DetourTransactionCommit();
}


VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine)
{
    Syelog(SYELOG_SEVERITY_FATAL,
           "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

static BOOL s_bLog = 1;
static LONG s_nTlsIndent = -1;
static LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;

VOID _PrintEnter(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)(nIndent + 1));
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0) {
            // Copy characters.
        }
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _PrintExit(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent) - 1;
        ASSERT(nIndent >= 0);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)nIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0) {
            // Copy characters.
        }
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _Print(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0) {
            // Copy characters.
        }
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                szBuf, args);

        va_end(args);
    }

    SetLastError(dwErr);
}


VOID NullExport()
{
}

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        LONG nThread = InterlockedIncrement(&s_nThreadCnt);
        TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
    }
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        TlsSetValue(s_nTlsThread, (PVOID)0);
    }
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
    s_bLog = FALSE;
    s_nTlsIndent = TlsAlloc();
    s_nTlsThread = TlsAlloc();

    WCHAR wzExeName[MAX_PATH];
    s_hInst = hDll;

    GetModuleFileNameW(hDll, s_wzDllPath, ARRAYOF(s_wzDllPath));
    GetModuleFileNameW(NULL, wzExeName, ARRAYOF(wzExeName));

    SyelogOpen("tracessl", SYELOG_FACILITY_APPLICATION);
    Syelog(SYELOG_SEVERITY_INFORMATION,
           "##################################################################\n");
    Syelog(SYELOG_SEVERITY_INFORMATION,
           "### %ls\n", wzExeName);
    LONG error = AttachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);
    }

    ThreadAttach(hDll);

    s_bLog = TRUE;
    return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
    ThreadDetach(hDll);
    s_bLog = FALSE;

    LONG error = DetachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);
    }

    Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
    SyelogClose(FALSE);

    if (s_nTlsIndent >= 0) {
        TlsFree(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        TlsFree(s_nTlsThread);
    }

	

    return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    switch (dwReason) {
      case DLL_PROCESS_ATTACH:
        printf("tracessl.dll: Starting.\n");
        fflush(stdout);
        Sleep(50);
        Sleep(50);
        DetourRestoreAfterWith();
        return ProcessAttach(hModule);
      case DLL_PROCESS_DETACH:
        return ProcessDetach(hModule);
      case DLL_THREAD_ATTACH:
        return ThreadAttach(hModule);
      case DLL_THREAD_DETACH:
        return ThreadDetach(hModule);
    }
    return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

