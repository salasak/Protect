// dllmain.cpp : 定义 DLL 应用程序的入口点。
// DLLCheck.cpp : Defines the entry point for the DLL application.
//

#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <string>

#include <tlhelp32.h>
#include <Softpub.h>
#include <Wincrypt.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wintrust.lib")
#include <iostream>
using namespace std;

bool ReRouteAPI( HMODULE hMod, char* pszDllName,
	char* pszFunctionName,DWORD dwNewAddress);
//void WINAPI MyFunction(DWORD dw);
HMODULE WINAPI MyFunction(LPCSTR lpLibFileName);
//void WINAPI MyFunction(DWORD lpLibFileName);

const char* DLL_SHAREMEM = "DLLNAME_SHAREMEM";

string g_Key = "7ef07bb2d0396a3fec8fe117139186f528b87b67";

HMODULE GetSelfModuleHandle()
{
	MEMORY_BASIC_INFORMATION mbi;
	return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
}

#pragma region anti inject dll
typedef LONG NTSTATUS;  
typedef NTSTATUS (WINAPI *NTQUERYINFORMATIONTHREAD)(  
	HANDLE ThreadHandle,   
	ULONG ThreadInformationClass,   
	PVOID ThreadInformation,   
	ULONG ThreadInformationLength,   
	PULONG ReturnLength); 
typedef enum _THREADINFOCLASS {  
	ThreadBasicInformation,  
	ThreadTimes,  
	ThreadPriority,  
	ThreadBasePriority,  
	ThreadAffinityMask,  
	ThreadImpersonationToken,  
	ThreadDescriptorTableEntry,  
	ThreadEnableAlignmentFaultFixup,  
	ThreadEventPair_Reusable,  
	ThreadQuerySetWin32StartAddress,  
	ThreadZeroTlsCell,  
	ThreadPerformanceCount,  
	ThreadAmILastThread,  
	ThreadIdealProcessor,  
	ThreadPriorityBoost,  
	ThreadSetTlsArrayAddress,   // Obsolete  
	ThreadIsIoPending,  
	ThreadHideFromDebugger,  
	ThreadBreakOnTermination,  
	ThreadSwitchLegacyState,  
	ThreadIsTerminated,  
	ThreadLastSystemCall,  
	ThreadIoPriority,  
	ThreadCycleTime,  
	ThreadPagePriority,  
	ThreadActualBasePriority,  
	ThreadTebInformation,  
	ThreadCSwitchMon,          // Obsolete  
	ThreadCSwitchPmu,  
	ThreadWow64Context,  
	ThreadGroupInformation,  
	ThreadUmsInformation,      // UMS  
	ThreadCounterProfiling,  
	ThreadIdealProcessorEx,  
	MaxThreadInfoClass  
} THREADINFOCLASS;  

NTQUERYINFORMATIONTHREAD NtQueryInformationThreadtion= NULL;

void Check_addr(int Thread_addr,PTHREADENTRY32 te32)
{
	int ProcAddr = (int)GetProcAddress(GetModuleHandleA("Kernel32.dll"),"LoadLibraryA");
	int ProcAddr2 =  (int)GetProcAddress(GetModuleHandleA("Kernel32.dll"),"LoadLibraryW");

	if (Thread_addr==ProcAddr || Thread_addr == ProcAddr2)
	{
		if(MessageBoxA(NULL,"发现一个刚被注入的线程，是否退出程序？","危险",MB_YESNO)==IDYES)
		{
			ExitProcess(-1);
			//TerminateThread(OpenThread(THREAD_ALL_ACCESS,true,te32->th32ThreadID),0);			
			
			return;
		}
	}
	return;

}
DWORD GetThreadStartAddr1(DWORD dwThreadId) ;

BOOL RefreshThreadList (DWORD dwOwnerPID) 
{ 
	HANDLE        hThreadSnap = NULL; 
	BOOL          bRet        = FALSE; 
	THREADENTRY32 te32        = {0}; 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	if (hThreadSnap == INVALID_HANDLE_VALUE) 
		return (FALSE); 
	te32.dwSize = sizeof(THREADENTRY32); 
	if (Thread32First(hThreadSnap, &te32)) 
	{ 
		do 
		{ 
			if (te32.th32OwnerProcessID == dwOwnerPID) 
			{ 
				Check_addr(GetThreadStartAddr1(te32.th32ThreadID),&te32);
			} 
		} 
		while (Thread32Next(hThreadSnap, &te32)); 
		bRet = TRUE; 
	} 
	else 
		bRet = FALSE;        
	CloseHandle (hThreadSnap);
	return (bRet); 
}

DWORD GetThreadStartAddr1(DWORD dwThreadId)  
{  
	HMODULE hNtdll = LoadLibrary("ntdll.dll");  
	if (!hNtdll)  
	{  
		return 0;  
	} 
	NTQUERYINFORMATIONTHREAD NtQueryInformationThread = NULL;  
	NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)  
		GetProcAddress(hNtdll, "NtQueryInformationThread");  
	if (!NtQueryInformationThread)  
	{  
		return 0;  
	} 
	HANDLE ThreadHandle = NULL;  
	ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);  
	if (!ThreadHandle)  
	{  
		return 0;  
	} 
	DWORD dwStaAddr = NULL;  
	DWORD dwReturnLength = 0;  
	if(NtQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress,  
		&dwStaAddr,4, &dwReturnLength))  
	{  
		return 0;  
	} 
	//char ss[25]={0};
	//sprintf_s(ss,25,"address:%d",dwStaAddr);
	//MessageBox(NULL,ss,NULL,NULL);
	return dwStaAddr;  
}

#pragma endregion anti inject dll

// On Load of DLL which it is attached to a executable, on that time, we 
// reroute the API, to our function.
BOOL APIENTRY DllMain( HANDLE hModule, 
	DWORD  ul_reason_for_call, 
	LPVOID lpReserved
	)
{
	OutputDebugString( "DLL is entered....." );
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			//ReRouteAPI(GetModuleHandle(NULL),"kernel32.dll","LoadLibraryA",(DWORD)MyFunction );
			break;
		}
	case DLL_THREAD_ATTACH:
		{			
			RefreshThreadList(GetCurrentProcessId());
			//return FALSE;
			break;
		}

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

IMAGE_IMPORT_DESCRIPTOR* GetImportDescriptor(HMODULE hMod, char* pszDllName )
{
	IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*)hMod; 
	IMAGE_OPTIONAL_HEADER* pOptionHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)hMod + pDOSHeader->e_lfanew + 24);
	IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + 
		pOptionHeader->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	char* pszImpAddr = 0;
	while( pImportDesc->FirstThunk)
	{
		pszImpAddr = (char*)(( BYTE* )hMod+ pImportDesc->Name );
		if( stricmp( pszDllName, pszImpAddr ))
		{
			pImportDesc++;
			continue;
		}
		else
		{
			return pImportDesc;   
		}
	}
	return NULL;
}

IMAGE_THUNK_DATA* GetOriginalFirstThunk(HMODULE hMod,IMAGE_IMPORT_DESCRIPTOR* pImportDesc )
{
	return (IMAGE_THUNK_DATA*)((BYTE*)hMod+ pImportDesc->OriginalFirstThunk );
}

IMAGE_THUNK_DATA* GetFirstThunk( HMODULE hMod,IMAGE_IMPORT_DESCRIPTOR* pImportDesc )
{
	return (IMAGE_THUNK_DATA*)((BYTE*)hMod+ pImportDesc->FirstThunk);
}

DWORD* GetCurrentFunctAddr(  HMODULE hMod,
	IMAGE_THUNK_DATA* pOriginalFirstThunk, 
	IMAGE_THUNK_DATA* pFirstThunk,
	char* pszFunctionName )
{
	char* szTest;

	while(pOriginalFirstThunk->u1.Function)
	{ 
		szTest = (char*)((BYTE*)hMod + (DWORD)pOriginalFirstThunk->u1.AddressOfData+2);
		if(stricmp(pszFunctionName,szTest)==0)
		{
			return &pFirstThunk->u1.Function;
		}
		pOriginalFirstThunk++; 
		pFirstThunk++;
	}

	return NULL;
}

bool ChangeAddress(DWORD* dwOldAddress,DWORD dwNewAddress)
{
	DWORD dwOld;
	if (!(VirtualProtect(dwOldAddress,4,PAGE_READWRITE,&dwOld))) 
	{
		return false;
	}
	*dwOldAddress = dwNewAddress;
	if (!(VirtualProtect(dwOldAddress,4,PAGE_EXECUTE,&dwOld))) 
	{
		return false;
	}
	else
	{
		OutputDebugString( "Change Address Final.." );
		return true;
	}
}

bool ReRouteAPI( HMODULE hMod, char* pszDllName, 
	char* pszFunctionName,DWORD dwNewAddress)
{
	OutputDebugString( "ReRouteAPI is entered....." );
	IMAGE_IMPORT_DESCRIPTOR* IID = GetImportDescriptor(hMod,pszDllName);
	if (IID == NULL) return false;
	IMAGE_THUNK_DATA* OriginalFirstThunk = GetOriginalFirstThunk(hMod,IID);
	IMAGE_THUNK_DATA* FirstThunk = GetFirstThunk(hMod,IID);
	OutputDebugString( "Change Address start.." );
	DWORD* dwOldFunctionAddress = GetCurrentFunctAddr( hMod,OriginalFirstThunk,
		FirstThunk,pszFunctionName);
	if (dwOldFunctionAddress == NULL) return false;
	return ChangeAddress(dwOldFunctionAddress,dwNewAddress);
}  

const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string hexStr(unsigned char *data, int len)
{
	std::string s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

BOOL VerifyCertHashValue(const  WINTRUST_DATA &sWintrustData)
{
	BOOL isEqual = FALSE;

	CRYPT_PROVIDER_DATA const *psProvData     = NULL;
	CRYPT_PROVIDER_SGNR       *psProvSigner   = NULL;
	CRYPT_PROVIDER_CERT       *psProvCert     = NULL;

	psProvData = WTHelperProvDataFromStateData(sWintrustData.hWVTStateData);
	if (psProvData)
	{
		psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0 , FALSE, 0);
		if (psProvSigner)
		{           
			psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0);
			if (psProvCert)
			{
				DWORD len =0;
				CertGetCertificateContextProperty(psProvCert->pCert, CERT_HASH_PROP_ID, NULL, &len);
				LPBYTE Thumbprint = new BYTE[len+1];
				memset(Thumbprint,0,(len+1)*sizeof(BYTE));

				CertGetCertificateContextProperty(psProvCert->pCert,CERT_HASH_PROP_ID,Thumbprint,&len);
				
				string  strThumb =hexStr(Thumbprint,len);

				std::cout<<strThumb<<std::endl;
				std::cout<<g_Key<<std::endl;
				if(g_Key.compare(strThumb) == 0)
					isEqual = TRUE;
				delete[] Thumbprint;
			}

		}
	}

	return isEqual;
}

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	BOOL isValidate=FALSE;

    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    
    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus) 
    {
        case ERROR_SUCCESS:
            /*
            Signed file:
                - Hash that represents the subject is trusted.

                - Trusted publisher without any verification errors.

                - UI was disabled in dwUIChoice. No publisher or 
                    time stamp chain errors.

                - UI was enabled in dwUIChoice and the user clicked 
                    "Yes" when asked to install and run the signed 
                    subject.
            */
            wprintf_s(L"The file \"%s\" is signed and the signature "
                L"was verified.\n",
                pwszSourceFile);
			isValidate =TRUE;
            break;
        
        case TRUST_E_NOSIGNATURE:
            // The file was not signed or had a signature 
            // that was not valid.

            // Get the reason for no signature.
            dwLastError = GetLastError();
            if (TRUST_E_NOSIGNATURE == dwLastError ||
                    TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                    TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
            {
                // The file was not signed.
                wprintf_s(L"The file \"%s\" is not signed.\n",
                    pwszSourceFile);
            } 
            else 
            {
                // The signature was not valid or there was an error 
                // opening the file.
                wprintf_s(L"An unknown error occurred trying to "
                    L"verify the signature of the \"%s\" file.\n",
                    pwszSourceFile);
            }
			isValidate =FALSE;
            break;
        default:
            isValidate = VerifyCertHashValue(WinTrustData);
            wprintf_s(L"Error is: 0x%x.\n",
                lStatus);


            break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return isValidate;
}

//将char* 转成wchar_t*的实现函数如下：
void c2w(wchar_t *pwstr,size_t len,const char *str)
{
	if(str)
	{
		size_t nu = strlen(str);
		size_t n =(size_t)MultiByteToWideChar(CP_ACP,0,(const char *)str,(int)nu,NULL,0);
		if(n>=len)n=len-1;
		MultiByteToWideChar(CP_ACP,0,(const char *)str,(int)nu,pwstr,(int)n);
		pwstr[n]=0;
	}
}

HMODULE WINAPI MyFunction(LPCTSTR lpLibFileName )
{
	OutputDebugString(lpLibFileName);

	// To Send the information to the server informing that,
	// LoadLibrary is invoked.
	//::MessageBox(NULL,g_Key.c_str(),NULL,NULL);	

	int len = strlen(lpLibFileName)+1;
	wchar_t *pwstr = new wchar_t[len];
	memset(pwstr,0,len);
	c2w(pwstr,len,lpLibFileName);

	if(VerifyEmbeddedSignature(pwstr))
	{
		//::MessageBox(NULL,"success",NULL,NULL);
	}
	else
	{

		//::MessageBox(NULL,"fail",NULL,NULL);
		return NULL;
	}
	//return NULL;
	return LoadLibraryA(lpLibFileName);
}




// This is the constructor of a class that has been exported.
// see DLLCheck.h for the class definition

extern "C" void __stdcall  CheckThumb(const char* pThumb){
	g_Key = string(pThumb);
}
