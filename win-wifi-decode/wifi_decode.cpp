/**
 *  The MIT License:
 *
 *  Copyright © 2013 Kevin Devine
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction,  including without limitation
 *  the rights to use,  copy,  modify,  merge,  publish,  distribute, 
 *  sublicense,  and/or sell copies of the Software,  and to permit persons to
 *  whom the Software is furnished to do so,  subject to the following
 *  conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE, 
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *  OTHER DEALINGS IN THE SOFTWARE.
 */
#define _WIN32_IE 0x0500
#define UNICODE

#include <windows.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <tlhelp32.h>
#include <msxml2.h>
#include <atlbase.h>

#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "Shell32.lib")
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "oleaut32.lib")
#pragma comment (lib, "msxml2.lib")

/**
 *
 *  Determines if process token is elevated
 *  Returns TRUE or FALSE
 *
 */
BOOL isElevated(VOID) {
  HANDLE hToken;
	BOOL bResult = FALSE;
  
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION te;
    DWORD dwSize;
    if (GetTokenInformation(hToken, TokenElevation, &te, 
        sizeof(TOKEN_ELEVATION), &dwSize)) {
		  bResult = te.TokenIsElevated != 0;
    }
    CloseHandle(hToken);
	}
  return bResult;
}

/**
 *
 *  Enables or disables a named privilege in token
 *  Returns TRUE or FALSE
 *
 */
BOOL SetPrivilege(wchar_t szPrivilege[], BOOL bEnable) {
  HANDLE hToken;
  BOOL bResult;
  
  bResult = OpenProcessToken(GetCurrentProcess(), 
    TOKEN_ADJUST_PRIVILEGES, &hToken);
  
  if (bResult) {
    LUID luid;
    bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
    if (bResult) {
      TOKEN_PRIVILEGES tp;
      
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;

      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
  }
  return bResult;
}

/**
 * 
 *  Convert error code to readable text
 *
 */
void Error(wchar_t szStr[], DWORD dwError) {
  PWCHAR pMsg;

  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&pMsg, 
      0, NULL);

  wprintf(L"\n\n  %s : %s", szStr, pMsg);
  LocalFree(pMsg);
}

/**
 *
 *  Obtain process id of process name
 *
 *  Returns process id or zero
 *
 */
DWORD GetProcessId(wchar_t szName[]) {
  DWORD dwId   = 0;
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  
  if (hSnap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    BOOL bResult = Process32First(hSnap, &pe32);
    while (bResult) {
      if (lstrcmpi(pe32.szExeFile, szName) == 0) {
        dwId = pe32.th32ProcessID;
        break;
      }
      bResult = Process32Next(hSnap, &pe32);
    }
    CloseHandle(hSnap);
  }
  return dwId;
}

BOOL ImpersonateSystem(VOID) {
  BOOL bImpersonating = FALSE;
  // get id of a LocalSystem process
  DWORD dwId = GetProcessId(L"lsass.exe");
  if (dwId != 0) {
    // enable debug privilege
    if (SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      // attempt to open process
      HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwId);
      if (hProcess != NULL) {
        HANDLE hToken;
        // attempt to open process token
        if (OpenProcessToken(hProcess, 
            TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
          // attempt to impersonate LocalSystem
          bImpersonating = ImpersonateLoggedOnUser(hToken);
          if (!bImpersonating) {
            Error(L"ImpersonateLoggedOnUser failed : ", GetLastError());
          }
          CloseHandle(hToken);
        } else {
          Error(L"OpenProcessToken failed : ", GetLastError());
        }
        CloseHandle(hProcess);
      } else {
        Error(L"OpenProcess(\"lsass.exe\") failed : ", GetLastError());
      }
    } else {
      Error(L"SetPrivilege(SE_DEBUG_NAME, TRUE) failed : ", GetLastError());
    }
  } else {
    Error(L"GetProcessId(\"lsass.exe\") failed : ", GetLastError());
  }
  return bImpersonating;
}
    
/**
 *
 *  Impersonate token of LocalSystem process
 *  Decrypt key with CryptUnprotectData 
 *  Display both the ascii and hex value of key
 *  
 */
void DecryptKey(std::wstring key) {
  static bool bImpersonating = false;
  
  // if not impersonating LocalSystem
  if (!bImpersonating) {
    bImpersonating = ImpersonateSystem();
  }

  if (bImpersonating) {
    BYTE byteKey[1024];
    DWORD dwLength = 1024;
    DATA_BLOB in, out;

    CryptStringToBinary(key.c_str(), key.length(), 
        CRYPT_STRING_HEX, byteKey, &dwLength, 0, 0);
        
    in.pbData = byteKey;
    in.cbData = dwLength;
    
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
      if (out.cbData != 0) {
        wchar_t buffer[256] = {0};
        memcpy(buffer, out.pbData, out.cbData);
        printf("  %-20s  ", buffer);
        
        for (int i = 0; i < out.cbData; i++) {
          printf("%02x", out.pbData[i]);
        }
        LocalFree(out.pbData);
      }
    } else {
      Error(L"CryptUnprotectData()", GetLastError());
    }
  }
}

/**
 *
 *  obtains and returns text of node
 *
 */
std::wstring get_text(CComPtr<IXMLDOMDocument2> pDoc, BSTR nodeString) {
  std::wstring text = L"";
  CComPtr<IXMLDOMNode> pNode = NULL;
  HRESULT hr = pDoc->selectSingleNode(nodeString, &pNode);
  if (SUCCEEDED(hr) && pNode != NULL) {
    CComPtr<IXMLDOMNode> pChild = NULL;
    hr = pNode->get_firstChild(&pChild);
    if (SUCCEEDED(hr) && pChild != NULL) {
      CComBSTR bstrText;
      hr = pChild->get_text(&bstrText);
      if (SUCCEEDED(hr)) {
        text = bstrText;
      }
    }
  }
  return text;
}

// required to parse WLAN profiles
#define WLAN_NS L"xmlns:s=\"http://www.microsoft.com/networking/WLAN/profile/v1\""

/**
 *  
 *  DumpWLANProfile(wchar_t adapterGuid[], wchar_t profileGuid[])
 *  
 *
 */
void DumpWLANProfile(wchar_t adapterGuid[], wchar_t profileGuid[]) {
  wchar_t path[MAX_PATH];
  wchar_t programData[MAX_PATH];
  
  SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, programData);
  _snwprintf(path, MAX_PATH, L"%s\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\%s\\%s.xml", 
      programData, adapterGuid, profileGuid);
  
  HRESULT hr = CoInitialize(NULL);
  if (FAILED(hr)) {
    wprintf(L"\nCoInitialize() failed : %08x", hr);
    return;
  }
  
  CComPtr<IXMLDOMDocument2> pDoc;
  hr = CoCreateInstance(CLSID_DOMDocument30, NULL, CLSCTX_INPROC_SERVER,
      IID_IXMLDOMDocument2, (void**)&pDoc);
      
  if (SUCCEEDED(hr)) {
    VARIANT_BOOL bIsSuccessful;
    hr = pDoc->load(CComVariant(path), &bIsSuccessful);
    
    if (SUCCEEDED(hr) && bIsSuccessful) {
      CComVariant ns = WLAN_NS;
      hr = pDoc->setProperty(BSTR(L"SelectionNamespaces"), ns);
  
      if (SUCCEEDED(hr)) {
        std::wstring ssid, auth, enc, key;
        ssid = get_text(pDoc, 
            BSTR(L"/s:WLANProfile/s:SSIDConfig/s:SSID/s:name"));
        auth = get_text(pDoc, 
            BSTR(L"/s:WLANProfile/s:MSM/s:security/s:authEncryption/s:authentication"));
        enc  = get_text(pDoc, 
            BSTR(L"/s:WLANProfile/s:MSM/s:security/s:authEncryption/s:encryption"));
        key  = get_text(pDoc, 
            BSTR(L"/s:WLANProfile/s:MSM/s:security/s:sharedKey/s:keyMaterial"));
        
        wprintf(L"\n  %-20s  %-10s  %-20s", ssid.c_str(), auth.c_str(), enc.c_str());
        if (!key.empty()) {
          DecryptKey(key);
        }
      } else {
        wprintf(L"\n  IXMLDOMDocument2->setProperty() failed : %08x", hr);
      }
      ns = NULL;
    } else {
      wprintf(L"\n  IXMLDOMDocument2->load() failed : %08x", hr);
    }
    pDoc = NULL;
  } else {
    wprintf(L"\n  CoCreateInstance() failed : %08x", hr);
  }
  CoUninitialize();
}

/**
 *
 *  If available, obtain adapter description for GUID
 *
 */
std::wstring GetAdapterDescription(std::wstring guid) {
  static DWORD dwCtrlIdx = 0;
  LSTATUS lStatus;
  DWORD cbSize;
  std::wstring description = L"<unavailable>";
  
  if (dwCtrlIdx == 0) {
    cbSize = sizeof(DWORD);
    lStatus = SHGetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 
        L"Default", 0, &dwCtrlIdx, &cbSize);
    if (lStatus != ERROR_SUCCESS) {
      dwCtrlIdx = 1;
    }
  }
  wchar_t path[1024];
  _snwprintf(path, sizeof(path) / sizeof(wchar_t), 
      L"SYSTEM\\ControlSet%03i\\Control\\Network\\"
      L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", 
      dwCtrlIdx, guid.c_str());

  wchar_t pnpInstance[1024];
  cbSize = sizeof(pnpInstance) / sizeof(wchar_t);
  lStatus = SHGetValue(HKEY_LOCAL_MACHINE, path, L"PnpInstanceID", 
      0, pnpInstance, &cbSize);
  if (lStatus == ERROR_SUCCESS) {
    _snwprintf(path, 1024, L"SYSTEM\\ControlSet%03i\\Enum\\%s", 
        dwCtrlIdx, pnpInstance);
  
    wchar_t deviceDesc[1024];
    cbSize = sizeof(deviceDesc) / sizeof(wchar_t);
    lStatus = SHGetValue(HKEY_LOCAL_MACHINE, path, L"DeviceDesc", 
        0, &deviceDesc, &cbSize);
    PWCHAR pDesc = wcsrchr(deviceDesc, L';');
    if (pDesc != 0) {
      description = ++pDesc;
    }
  }
  return description;
}

DWORD EnumInterfaces(VOID) {
  HKEY hSubKey;
  DWORD dwError = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
      L"SOFTWARE\\Microsoft\\Wlansvc\\Interfaces", 0, 
      KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hSubKey);
  
  if (dwError != ERROR_SUCCESS) {
    Error(L"RegOpenKeyEx(\"SOFTWARE\\Microsoft\\Wlansvc\\Interfaces\"", dwError);
    return 0;
  }
  DWORD dwIndex = 0;
  
  while (dwError == ERROR_SUCCESS) {
    wchar_t adapterGuid[256];
    DWORD cbSize = sizeof(adapterGuid) / sizeof(wchar_t);
    dwError = RegEnumKeyEx(hSubKey, dwIndex, adapterGuid, 
        &cbSize, NULL, NULL, NULL, NULL);
    if (dwError == ERROR_SUCCESS) {
      std::wstring description = GetAdapterDescription(adapterGuid);
      wprintf(L"\n  %s", description.c_str());
      
      wprintf(L"\n  %-20s  %-10s  %-20s  %-20s  %-20s", 
          std::wstring(20, L'-').c_str(), 
          std::wstring(10, L'-').c_str(),  
          std::wstring(20, L'-').c_str(), 
          std::wstring(20, L'-').c_str(),
          std::wstring(20, L'-').c_str());
      
      wprintf(L"\n  %-20s  %-10s  %-20s  %-20s  %-20s", 
          L"SSID", L"Auth", L"Encryption", L"Key(Ascii)", L"Key(Hex)");
          
      wprintf(L"\n  %-20s  %-10s  %-20s  %-20s  %-20s", 
          std::wstring(20, L'-').c_str(), 
          std::wstring(10, L'-').c_str(),  
          std::wstring(20, L'-').c_str(), 
          std::wstring(20, L'-').c_str(),
          std::wstring(20, L'-').c_str());
      
      wchar_t profileList[4096*4];
      cbSize = sizeof(profileList) / sizeof(wchar_t);
      dwError = RegGetValue(hSubKey, adapterGuid, L"ProfileList", 
          RRF_RT_REG_MULTI_SZ, 0, profileList, &cbSize);
          
      if (dwError == ERROR_SUCCESS) {
        PWCHAR pProfileGuid = profileList;
        for (;;) {
          DumpWLANProfile(adapterGuid, pProfileGuid);
          pProfileGuid += wcslen(pProfileGuid) + 1;
          if (pProfileGuid[0] == 0) break;
        }
        wprintf(L"\n\n");
      } else {
        Error(L"RegGetValue()", dwError);
      }
    }
    dwIndex++;
  }
  RegCloseKey(hSubKey);
  return 0;
}

VOID ConsoleSetBufferWidth(SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
  
  if (X <= csbi.dwSize.X) return;
  csbi.dwSize.X  = X;
  SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), csbi.dwSize);  
}

int main(void) {
  ConsoleSetBufferWidth(300);
  
  puts("\n  Windows Wireless Key Dumper v1.0"
       "\n  Copyright (c) 2013 Kevin Devine\n");
  
  if (!isElevated()) {
    printf("\n  WARNING: Process token requires elevation . . .\n");
  }
  
  EnumInterfaces();
  printf("\n  Press any key to continue . . .");
  fgetc(stdin);
  return 0;
}
