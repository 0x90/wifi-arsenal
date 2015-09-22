// atheros_eeprom_tool.cpp : Defines the entry point for the application.
//
#include "stdafx.h"
#include <CommDlg.h>
#include "atheros_eeprom_tool.h"
#include <setupapi.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <string.h>

#define AR5416_EEPROM_MAGIC 0xa55a

#define READ_EEPROM_CODE 0x89A42004
#define WRITE_EEPROM_CODE 0x89A42008
#define GET_SIZE_CODE 0x89A4200C
#define GET_DEVICE_MEM_START 1
#define ENUM_DEVICES 2
#define EDITID 1

struct DEVNAME {
	char* Name;
	char* Instance;
};

HANDLE hWriteFile = INVALID_HANDLE_VALUE;
HWND hwndModchan = 0;
HWND hwndChoose = 0;
//HWND hwndCUSTOMRD = 0;
HINSTANCE hInst;
OPENFILENAME ofn;
char* ofnPath[MAX_PATH];
HWND hwndMain = 0;
char* tempPath[MAX_PATH];
char* exePath[MAX_PATH];
char driverPath[MAX_PATH];
char* commandLine[1024];
STARTUPINFO si;
PROCESS_INFORMATION pi;
DWORD numOfIO;
char phyMem[10];
SERVICE_STATUS srvStatus;
HLOCAL formattedError;
SP_DEVINFO_DATA diData;
char DevInstanceId[255];
DWORDLONG resMemStart = 0;
unsigned char patchOpCap = 0;
unsigned short patchRegDmn = 0;
unsigned long long patchMAC = 0;
DWORDLONG phyAddr;
unsigned int eepromLength;
DEVNAME* deviceEnum;
char* workDevInstance = 0;
SC_HANDLE hDevice;
SC_HANDLE hSCM;
HANDLE hDriver;
WNDPROC CUSTOMRD_WinProc;
char oldMACText[14] = "";
char oldRDText[5] = "";
char newText[14];
char RDText[6];
char MACText[13];
char MACPart[10];
unsigned char* eeprom = 0;
unsigned char* patchedEeprom = 0;
bool bWarned = false;
unsigned int devCount = 0;
bool bReadOnly = false;
bool bNoCard = false;
bool bDriverLoaded = false;

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS 
fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
GetModuleHandle("kernel32"),"IsWow64Process");

BOOL DumpDeviceResourcesOfType(__in DEVINST DevInst, __in HMACHINE MachineHandle, __in LOG_CONF Config, __in RESOURCEID ReqResId)
{
    RES_DES prevResDes = (RES_DES)Config;
    RES_DES resDes = 0;
    RESOURCEID resId = ReqResId;
    ULONG dataSize;
    PBYTE resDesData;
    BOOL  retval = FALSE;

    UNREFERENCED_PARAMETER(DevInst);

    while(CM_Get_Next_Res_Des_Ex(&resDes,prevResDes,ReqResId,&resId,0,MachineHandle)==CR_SUCCESS) {
        if(prevResDes != Config) {
            CM_Free_Res_Des_Handle(prevResDes);
        }
        prevResDes = resDes;
        if(CM_Get_Res_Des_Data_Size_Ex(&dataSize,resDes,0,MachineHandle)!=CR_SUCCESS) {
            continue;
        }
        resDesData = new BYTE[dataSize];
        if(!resDesData) {
            continue;
        }
        if(CM_Get_Res_Des_Data_Ex(resDes,resDesData,dataSize,0,MachineHandle)!=CR_SUCCESS) {
            delete [] resDesData;
            continue;
        }
        switch(resId) {
            case ResType_Mem: {

                PMEM_RESOURCE  pMemData = (PMEM_RESOURCE)resDesData;
                if(pMemData->MEM_Header.MD_Alloc_End-pMemData->MEM_Header.MD_Alloc_Base+1) {
					resMemStart = pMemData->MEM_Header.MD_Alloc_Base;
                    _tprintf(TEXT("MEM : %08I64x-%08I64x\n"),pMemData->MEM_Header.MD_Alloc_Base,pMemData->MEM_Header.MD_Alloc_End);
                    retval = TRUE;
                }
                break;
            }

            case ResType_IO: {

                PIO_RESOURCE   pIoData = (PIO_RESOURCE)resDesData;
                if(pIoData->IO_Header.IOD_Alloc_End-pIoData->IO_Header.IOD_Alloc_Base+1) {
                    _tprintf(TEXT("IO  : %04I64x-%04I64x\n"),pIoData->IO_Header.IOD_Alloc_Base,pIoData->IO_Header.IOD_Alloc_End);
                    retval = TRUE;
                }
                break;
            }

            case ResType_DMA: {

                PDMA_RESOURCE pDmaData = (PDMA_RESOURCE)resDesData;
                _tprintf(TEXT("DMA : %u\n"),pDmaData->DMA_Header.DD_Alloc_Chan);
                retval = TRUE;
                break;
            }

            case ResType_IRQ: {

                PIRQ_RESOURCE  pIrqData = (PIRQ_RESOURCE)resDesData;

                _tprintf(TEXT("IRQ : %u\n"),pIrqData->IRQ_Header.IRQD_Alloc_Num);
                retval = TRUE;
                break;
            }
        }
        delete [] resDesData;
    }
    if(prevResDes != Config) {
        CM_Free_Res_Des_Handle(prevResDes);
    }
    return retval;
}

BOOL DumpDeviceResources(__in HDEVINFO Devs, __in PSP_DEVINFO_DATA DevInfo)
/*++

Routine Description:

    Dump Resources to stdout

Arguments:

    Devs    )_ uniquely identify device
    DevInfo )

Return Value:

    none

--*/
{
    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;
    ULONG status = 0;
    ULONG problem = 0;
    LOG_CONF config = 0;
    BOOL haveConfig = FALSE;

    //
    // see what state the device is in
    //
    devInfoListDetail.cbSize = sizeof(devInfoListDetail);
    if((!SetupDiGetDeviceInfoListDetail(Devs,&devInfoListDetail)) ||
            (CM_Get_DevNode_Status_Ex(&status,&problem,DevInfo->DevInst,0,devInfoListDetail.RemoteMachineHandle)!=CR_SUCCESS)) {
        return FALSE;
    }

    //
    // see if the device is running and what resources it might be using
    //
    if(!(status & DN_HAS_PROBLEM)) {
        //
        // If this device is running, does this devinst have a ALLOC log config?
        //
        if (CM_Get_First_Log_Conf_Ex(&config,
                                     DevInfo->DevInst,
                                     ALLOC_LOG_CONF,
                                     devInfoListDetail.RemoteMachineHandle) == CR_SUCCESS) {
            haveConfig = TRUE;
        }
    }
    if(!haveConfig) {
        //
        // If no config so far, does it have a FORCED log config?
        // (note that technically these resources might be used by another device
        // but is useful info to show)
        //
        if (CM_Get_First_Log_Conf_Ex(&config,
                                     DevInfo->DevInst,
                                     FORCED_LOG_CONF,
                                     devInfoListDetail.RemoteMachineHandle) == CR_SUCCESS) {
            haveConfig = TRUE;
        }
    }

    if(!haveConfig) {
        //
        // if there's a hardware-disabled problem, boot-config isn't valid
        // otherwise use this if we don't have anything else
        //
        if(!(status & DN_HAS_PROBLEM) || (problem != CM_PROB_HARDWARE_DISABLED)) {
            //
            // Does it have a BOOT log config?
            //
            if (CM_Get_First_Log_Conf_Ex(&config,
                                         DevInfo->DevInst,
                                         BOOT_LOG_CONF,
                                         devInfoListDetail.RemoteMachineHandle) == CR_SUCCESS) {
                haveConfig = TRUE;
            }
        }
    }

    if(!haveConfig) {
        //
        // if we don't have any configuration, display an apropriate message
        //
        return TRUE;
    }

    //
    // dump resources
    //
    DumpDeviceResourcesOfType(DevInfo->DevInst,devInfoListDetail.RemoteMachineHandle,config,ResType_Mem);

    //
    // release handle
    //
    CM_Free_Log_Conf_Handle(config);

    return TRUE;
}

unsigned int getDeviceInfo(char* instanceName, unsigned int operationId) {
       HDEVINFO hDevInfo;
       SP_DEVINFO_DATA DeviceInfoData;
       DWORD i, RequiredSize;

	   if (operationId == GET_DEVICE_MEM_START) resMemStart = 0;

       // Create a HDEVINFO with all present devices.
       hDevInfo = SetupDiGetClassDevs(NULL,
           0, // Enumerator
           0,
           DIGCF_PRESENT | DIGCF_ALLCLASSES );
       
       if (hDevInfo == INVALID_HANDLE_VALUE)
       {
           // Insert error handling here.
           return 1;
       }
       
       // Enumerate through all devices in Set.
       
       DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
       for (i=0;SetupDiEnumDeviceInfo(hDevInfo,i,
           &DeviceInfoData);i++)
       {
           DWORD DataT;
           LPTSTR buffer = NULL;
           DWORD buffersize = 0;
           
           //
           // Call function with null to begin with, 
           // then use the returned buffer size (doubled)
           // to Alloc the buffer. Keep calling until
           // success or an unknown failure.
           //
           //  Double the returned buffersize to correct
           //  for underlying legacy CM functions that 
           //  return an incorrect buffersize value on 
           //  DBCS/MBCS systems.
           // 
           while (!SetupDiGetDeviceRegistryProperty(
               hDevInfo,
               &DeviceInfoData,
               SPDRP_DEVICEDESC,
               &DataT,
               (PBYTE)buffer,
               buffersize,
               &buffersize))
           {
               if (GetLastError() == 
                   ERROR_INSUFFICIENT_BUFFER)
               {
                   // Change the buffer size.
                   if (buffer) LocalFree(buffer);
                   // Double the size to avoid problems on 
                   // W2k MBCS systems per KB 888609. 
                   buffer = (LPTSTR)LocalAlloc(LPTR,buffersize * 2);
               }
               else
               {
                   // Insert error handling here.
                   break;
               }
           }

		   SetupDiGetDeviceInstanceId(hDevInfo, &DeviceInfoData, (PSTR)DevInstanceId, 255, &RequiredSize);

		   if (strstr(DevInstanceId, instanceName) != 0){
			   if (operationId == GET_DEVICE_MEM_START) DumpDeviceResources(hDevInfo, &DeviceInfoData);
			   else if (operationId == ENUM_DEVICES) {
				   char* deviceString = (char*)malloc(strlen(DevInstanceId)+1);
				   int deviceStringLen = (int)strlen(DevInstanceId)+1;
#if __STDC_WANT_SECURE_LIB__
				   strncpy_s(deviceString, deviceStringLen, DevInstanceId, deviceStringLen);
#else
				   strncpy(deviceString, DevInstanceId, deviceStringLen);
#endif
				   deviceEnum[devCount].Instance = (char*)deviceString;
				   deviceString = (char*)malloc(strlen(buffer)+1);
				   deviceStringLen = (int)strlen(buffer)+1;
#if __STDC_WANT_SECURE_LIB__
				   strncpy_s(deviceString, deviceStringLen, buffer, deviceStringLen);
#else
				   strncpy(deviceString, buffer, deviceStringLen);
#endif

				   deviceEnum[devCount].Name = (char*)deviceString;
				   devCount++;
			   }
		   }
           
		   //printf("Result:[%s]\nDevId:%s\n\n",buffer, DevInstanceId);
           
           if (buffer) LocalFree(buffer);
       }
       
       
       if ( GetLastError()!=NO_ERROR &&
            GetLastError()!=ERROR_NO_MORE_ITEMS )
       {
           // Insert error handling here.
           return 1;
       }
       
       //  Cleanup
       SetupDiDestroyDeviceInfoList(hDevInfo);
       
       return 0;
}
 
BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;
 
    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            // handle error
        }
    }
    return bIsWow64;
}

DWORD atoi_h (char* aInt){
	DWORD int_h = 0;
	for (int i = 0; aInt[i]; i++){
		int_h <<= 4;
		if (i >= 8){
			int_h = 0;
			break;
		}
		else if ((aInt[i] >= 0x30 && aInt[i] <= 0x39)){
			int_h += aInt[i]-0x30;
		}
		else if ((aInt[i] >= 0x41 && aInt[i] <= 0x46)){
			int_h += aInt[i]-0x37;
		}
		else if ((aInt[i] >= 0x61 && aInt[i] <= 0x66)){
			int_h += aInt[i]-0x57;
		}
		else {
			int_h = 0;
			break;
		}
	}
	return int_h;
}

void showErrorMessage(LPCSTR msgText, LPCSTR msgCaption, unsigned int errorCode){
	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER+FORMAT_MESSAGE_FROM_SYSTEM, NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&formattedError, 1024, NULL)){
		char* errorMsg = (char*)malloc(strlen(msgText) + strlen((char*)formattedError) + 100);
		wsprintfA(errorMsg, "%s\n\nDetails:\n%s", msgText, (char*)formattedError);
		MessageBox(hwndMain, errorMsg, msgCaption, MB_ICONERROR);
		free((void*)errorMsg);
	}
	else MessageBox(hwndMain, msgText, msgCaption, MB_ICONERROR);
	return;
}

BOOL LoadDriver(){
	int i = 0;

	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCM){
		showErrorMessage("Can't connect to service control manager", "Error", GetLastError());
		return false;
	}
	GetModuleFileName(GetModuleHandle(0), (LPSTR)driverPath, MAX_PATH);
	for (i = (int)strlen((char*)driverPath); i; i--){
		if (driverPath[i-1] == '\\'){
			driverPath[i] = 0;
			break;
		}
	}
#ifndef _WIN64
	if (IsWow64()){
#endif
#if __STDC_WANT_SECURE_LIB__
		strncat_s((char*)driverPath, sizeof(driverPath), "ath64.sys", sizeof(driverPath));
#else
		strncat((char*)driverPath, "ath64.sys", sizeof(driverPath));
#endif
#ifndef _WIN64
	}
	else {
#if __STDC_WANT_SECURE_LIB__
		strncat_s((char*)driverPath, sizeof(driverPath), "ath32.sys", sizeof(driverPath));
#else
		strncat((char*)driverPath, "ath32.sys", sizeof(driverPath));
#endif
	}
#endif
	HANDLE hFile = CreateFile((LPCSTR)driverPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE){
		CloseServiceHandle(hSCM);
		if (IsWow64()) showErrorMessage("Can't open ath64.sys", "Error", GetLastError());
		else showErrorMessage("Can't open ath32.sys", "Error", GetLastError());
		return false;
	}
	else CloseHandle(hFile);
	hDevice = CreateService(hSCM, "atheeprom", "atheeprom", SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, (LPSTR)driverPath, 0, 0, 0, 0, 0);
	if (!hDevice){
		hDevice = OpenService(hSCM, "atheeprom", SC_MANAGER_ALL_ACCESS);
		if (hDevice){
			ControlService(hDevice, SERVICE_CONTROL_STOP, &srvStatus);
			DeleteService(hDevice);
			CloseServiceHandle(hDevice);
			hDevice = CreateService(hSCM, "atheeprom", "atheeprom", SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, (LPSTR)driverPath, 0, 0, 0, 0, 0);
		}
	}
	if (!hDevice){
		CloseServiceHandle(hSCM);
		showErrorMessage("Can't open atheeprom service", "Error", GetLastError());
		return false;
	}
	if (StartService(hDevice, 0, 0) == 0 && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING){
		CloseServiceHandle(hDevice);
		CloseServiceHandle(hSCM);
		showErrorMessage("Can't start service", "Error", GetLastError());
		return false;
	}

	hDriver = CreateFile("\\\\.\\atheeprom", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDriver == INVALID_HANDLE_VALUE){
		CloseServiceHandle(hDevice);
		CloseServiceHandle(hSCM);
		showErrorMessage("Can't open driver", "Error", GetLastError());
		return false;
	}
	return true;
}

BOOL UnloadDriver(){
	CloseHandle(hDriver);
	ControlService(hDevice, SERVICE_CONTROL_STOP, &srvStatus);
	DeleteService(hDevice);
	CloseServiceHandle(hDevice);
	CloseServiceHandle(hSCM);
	return true;
}

void eeprom_crc_calc(unsigned char *rom, unsigned short *crcp)
{
	unsigned short crc = 0;
	int i;

	for (i=0; i<504; i+=2) {
		if ((130 == i) || (128 > i)) continue;
		crc ^= *(unsigned short *)(rom + i);
	}
	crc ^= 0xFFFF;

	if (crcp)
		*crcp = crc;
}

void CorrectChecksum(unsigned eepromLength)
{
	DWORD numOfIO;
	unsigned char* eepromRead = (unsigned char*)calloc(eepromLength,1);
	unsigned char crc[2] = {0,0};

	if (DeviceIoControl(hDriver, READ_EEPROM_CODE, &phyAddr, 8, eepromRead, eepromLength, &numOfIO, NULL))
	{
		eeprom_crc_calc(eepromRead, (unsigned short *)crc);

		eepromRead[130] = crc[0];
		eepromRead[131] = crc[1];

		if (DeviceIoControl(hDriver, WRITE_EEPROM_CODE, eepromRead, eepromLength, 0, 0, &numOfIO, NULL))
		{
			MessageBox(hwndMain, "Successfully corrected checksum!", "Done", MB_ICONINFORMATION);
		}
		else if (GetLastError() == ERROR_IO_DEVICE)
		{
			MessageBox(hwndMain, "EEPROM COULD BE DAMAGED!! Please do not close this tool and try to write again!", "ERROR DURING WRITING PROCESS!!", MB_ICONERROR);
		}
		else
		{
			showErrorMessage("Write error. EEPROM not damaged", "Error", GetLastError());
		}
	}
	else
	{
		showErrorMessage("DeviceIoControl error", "Error", GetLastError());
	}

	free(eepromRead);
}

void ReadEEPROM(char* filename, unsigned eepromLength)
{
	DWORD numOfIO;
	unsigned char* eepromRead = (unsigned char*)calloc(eepromLength,1);
	
	if (DeviceIoControl(hDriver, READ_EEPROM_CODE, &phyAddr, 8, eepromRead, eepromLength, &numOfIO, NULL))
	{
		HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, eepromRead, eepromLength, &numOfIO, 0);
			CloseHandle(hFile);
			MessageBox(hwndMain, "Dumped", "Done", MB_ICONINFORMATION);
		}
		else
		{
			showErrorMessage("Can't open file for save", "Error", GetLastError());
		}
	}
	else
	{
		showErrorMessage("DeviceIoControl error", "Error", GetLastError());
	}
	free(eepromRead);
}

void WriteEEPROM(char* filename, unsigned eepromLength)
{
	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		showErrorMessage("Can't open or lock file", "Error", GetLastError());
		return;
	}
	
	size_t fSize = GetFileSize(hFile, 0);

	if(fSize != eepromLength)
	{
		MessageBox(hwndMain, "Image size doesn't match EEPROM size.", "Warning", MB_ICONWARNING);
	}
	else
	{
		DWORD numOfIO;
		unsigned char* eepromCopy = (unsigned char*)calloc(8 + eepromLength, 1);

		memcpy(eepromCopy, &phyAddr, 8);
		ReadFile(hFile, eepromCopy + 8, (DWORD)fSize, &numOfIO, 0);

		if (*(WORD*)(eepromCopy + 8) != AR5416_EEPROM_MAGIC)
		{
			MessageBox(hwndMain, "Invalid EEPROM image", "Error", MB_ICONERROR);
		}
		else
		{
			if (DeviceIoControl(hDriver, WRITE_EEPROM_CODE, eepromCopy, eepromLength + 8, 0, 0, &numOfIO, NULL))
			{
				MessageBox(hwndMain, "Successfully written", "Done", MB_ICONINFORMATION);
			}
			else if (GetLastError() == ERROR_IO_DEVICE)
			{
				MessageBox(hwndMain, "EEPROM COULD BE DAMAGED!! Please do not close this tool and try to write again!", "ERROR DURING WRITING PROCESS!!", MB_ICONERROR);
			}
			else
			{
				showErrorMessage("Write error. EEPROM not damaged", "Error", GetLastError());
			}
		}

		free(eepromCopy);
	}

	CloseHandle(hFile);
}

INT_PTR CALLBACK DialogProcChoose(HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	switch(uMsg){
		case WM_INITDIALOG:
			hwndChoose = hwndDlg;
			for (unsigned int i = 0; i < devCount; i++){
				SendDlgItemMessage(hwndDlg, IDC_DEVLIST, CB_ADDSTRING, 0, (LPARAM)deviceEnum[i].Name);
			}
			SendDlgItemMessage(hwndDlg, IDC_DEVLIST, CB_SELECTSTRING, (WPARAM)-1, (LPARAM)deviceEnum[0].Name);
			SetDlgItemText(hwndChoose, IDC_DEVINST, deviceEnum[0].Instance);
			return TRUE;
		case WM_COMMAND:
			if ((WORD)wParam == IDC_CHOK){
				workDevInstance = deviceEnum[SendDlgItemMessage(hwndDlg, IDC_DEVLIST, CB_GETCURSEL, 0, 0)].Instance;
				EndDialog(hwndDlg,TRUE);
			}
			else if (HIWORD (wParam) == CBN_SELCHANGE){
				SetDlgItemText(hwndChoose, IDC_DEVINST, deviceEnum[SendDlgItemMessage(hwndDlg, IDC_DEVLIST, CB_GETCURSEL, 0, 0)].Instance);
			}
			else return FALSE;
			return TRUE;
		case WM_CLOSE:
			EndDialog(hwndDlg,TRUE);
			return TRUE;
		case WM_DESTROY:
			EndDialog(hwndDlg,TRUE);
			return TRUE;
		default:
			return FALSE;
	}
}

INT_PTR CALLBACK DialogProcModchan(HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
	switch(uMsg){
		case WM_INITDIALOG:
			hwndModchan = hwndDlg;
			if (!bReadOnly){
				CheckDlgButton(hwndMain, IDC_OVERRIDE, true);
				CheckDlgButton(hwndModchan, IDC_24g, true);
			}
			else if (patchOpCap & 0x02) CheckDlgButton(hwndModchan, IDC_24g, true);

			if (patchRegDmn == 0x60) CheckDlgButton(hwndModchan, IDC_C60, true);
			else if (patchRegDmn == 0x63) CheckDlgButton(hwndModchan, IDC_C63, true);
			else if (patchRegDmn == 0x64) CheckDlgButton(hwndModchan, IDC_C64, true);
			else if (patchRegDmn == 0x66) CheckDlgButton(hwndModchan, IDC_C66, true);
			else if (patchRegDmn == 0x67) CheckDlgButton(hwndModchan, IDC_C67, true);
			else {
				CheckDlgButton(hwndModchan, IDC_RBCUSTOM, true);
				wsprintfA((char*)RDText, "%X", patchRegDmn);
				SetDlgItemText(hwndModchan, IDC_CUSTOMRD, (char*)RDText);
			}

			if (patchOpCap & 0x01) CheckDlgButton(hwndModchan, IDC_5a, true);
			/*if (patchOpCap & 0x02)*/
			if (!(patchOpCap & 0x04)) CheckDlgButton(hwndModchan, IDC_5n40, true);
			if (!(patchOpCap & 0x08)) CheckDlgButton(hwndModchan, IDC_24n40, true);
			if (!(patchOpCap & 0x10)) CheckDlgButton(hwndModchan, IDC_5n20, true);
			if (!(patchOpCap & 0x20)) CheckDlgButton(hwndModchan, IDC_24n20, true);

			for (int i = 0, j = 5; i < 6; i++, j--){
				unsigned char MACByte = (unsigned char)(patchMAC >> (j*8));
				if ((MACByte & 0xF0) < 0xA0){
					MACText[i*2] = ((MACByte & 0xF0) >> 4) + 0x30;
				}
				else {
					MACText[i*2] = ((MACByte & 0xF0) >> 4) + 0x37;
				}
				MACByte &= 0xF;
				if (MACByte < 0xA){
					MACText[i*2+1] = MACByte + 0x30;
				}
				else {
					MACText[i*2+1] = MACByte + 0x37;
				}
			}
			SetDlgItemText(hwndModchan, IDC_MAC, (char*)MACText);

			SendDlgItemMessage(hwndDlg, IDC_CUSTOMRD, EM_LIMITTEXT, 4, 0);
			SendDlgItemMessage(hwndDlg, IDC_MAC, EM_LIMITTEXT, 12, 0);

			if (bReadOnly){
				EnableWindow(GetDlgItem(hwndDlg, IDC_24n20), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_24n40), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_5a), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_5n20), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_5n40), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_C60), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_C63), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_C64), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_C66), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_C67), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_RBCUSTOM), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_CUSTOMRD), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_MAC), false);
				EnableWindow(GetDlgItem(hwndDlg, IDC_MCOK), false);
			}
			//hwndCUSTOMRD = GetDlgItem(hwndDlg, IDC_CUSTOMRD);
			//CUSTOMRD_WinProc = (WNDPROC)SetWindowLong(GetDlgItem(hwndDlg, IDC_CUSTOMRD), GWL_WNDPROC, (DWORD) CUSTOMRD_Proc);
			return TRUE;
		case WM_COMMAND:
			if (lParam && (LOWORD (wParam) == IDC_CUSTOMRD || LOWORD (wParam) == IDC_MAC) && HIWORD (wParam) == EN_UPDATE){
				for (unsigned int i = GetDlgItemText(hwndModchan, LOWORD (wParam), (char*)newText, 14); i; i--){
					if (
						(newText[i-1] >= 0x30 && newText[i-1] <= 0x39)
						||
						(newText[i-1] >= 0x41 && newText[i-1] <= 0x46)
						||
						(newText[i-1] >= 0x61 && newText[i-1] <= 0x66)
						) continue;
					else {
						if (LOWORD (wParam) == IDC_CUSTOMRD) SetDlgItemText(hwndModchan, LOWORD (wParam), (char*)oldRDText);
						else if (LOWORD (wParam) == IDC_MAC) SetDlgItemText(hwndModchan, LOWORD (wParam), (char*)oldMACText);
						return TRUE;
					}
				}
#if __STDC_WANT_SECURE_LIB__
				if (LOWORD (wParam) == IDC_CUSTOMRD) strncpy_s((char*)oldRDText, sizeof(oldRDText), (char*)newText, sizeof(oldRDText));
				else if (LOWORD (wParam) == IDC_MAC) strncpy_s((char*)oldMACText, sizeof(oldMACText), (char*)newText, sizeof(oldMACText));
#else
				if (LOWORD (wParam) == IDC_CUSTOMRD) strncpy((char*)oldRDText, (char*)newText, sizeof(oldRDText));
				else if (LOWORD (wParam) == IDC_MAC) strncpy((char*)oldMACText, (char*)newText, sizeof(oldMACText));
#endif
			}
			else if ((WORD)wParam == IDC_MCOK){
				if (IsDlgButtonChecked(hwndModchan, IDC_C60) == BST_CHECKED) patchRegDmn = 0x60;
				else if (IsDlgButtonChecked(hwndModchan, IDC_C63) == BST_CHECKED) patchRegDmn = 0x63;
				else if (IsDlgButtonChecked(hwndModchan, IDC_C64) == BST_CHECKED) patchRegDmn = 0x64;
				else if (IsDlgButtonChecked(hwndModchan, IDC_C66) == BST_CHECKED) patchRegDmn = 0x66;
				else if (IsDlgButtonChecked(hwndModchan, IDC_C67) == BST_CHECKED) patchRegDmn = 0x67;
				else {
					if (GetDlgItemText(hwndModchan, IDC_CUSTOMRD, (char*)RDText, 5)){
						patchRegDmn = (unsigned short)atoi_h((char*)RDText);
					}
					else {
						MessageBox(hwndMain, "Invalid RegDmn", "Error", MB_ICONERROR);
						return TRUE;
					}
				}

				unsigned int MACLength = GetDlgItemText(hwndModchan, IDC_MAC, (char*)MACText, 14);
				if (MACLength == 12){
					memcpy((char*)MACPart, (char*)MACText, MACLength-8);
					MACPart[MACLength-8] = 0;
					patchMAC = atoi_h((char*)MACPart);
					patchMAC <<= 32;
					memcpy((char*)MACPart, (char*)(MACText+MACLength-8), 8);
					MACPart[8] = 0;
					patchMAC += atoi_h((char*)MACPart);
				}
				else {
					MessageBox(hwndMain, "MAC must contain 12 chars", "Error", MB_ICONERROR);
					return TRUE;
				}

				patchOpCap = 0;

				if (IsDlgButtonChecked(hwndModchan, IDC_5a) == BST_CHECKED) patchOpCap |= 0x01;
				if (IsDlgButtonChecked(hwndModchan, IDC_24g) == BST_CHECKED) patchOpCap |= 0x02;
				if (IsDlgButtonChecked(hwndModchan, IDC_5n40) != BST_CHECKED) patchOpCap |= 0x04;
				if (IsDlgButtonChecked(hwndModchan, IDC_24n40) != BST_CHECKED) patchOpCap |= 0x08;
				if (IsDlgButtonChecked(hwndModchan, IDC_5n20) != BST_CHECKED) patchOpCap |= 0x10;
				if (IsDlgButtonChecked(hwndModchan, IDC_24n20) != BST_CHECKED) patchOpCap |= 0x20;
				EndDialog(hwndDlg,TRUE);
			}
			else if ((WORD)wParam == IDC_MCCANCEL){
				EndDialog(hwndDlg,TRUE);
			}
			else return FALSE;
			return TRUE;
		case WM_CLOSE:
			EndDialog(hwndDlg,TRUE);
			return TRUE;
		case WM_DESTROY:
			EndDialog(hwndDlg,TRUE);
			return TRUE;
		default:
			return FALSE;
	}
}

INT_PTR CALLBACK DialogProcMain(HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	switch(uMsg){
		case WM_INITDIALOG:
			hwndMain = hwndDlg;
			ofn.hwndOwner = hwndDlg;
			if (bNoCard){
				CheckDlgButton(hwndDlg, IDC_CHECKWRITE, true);
				EnableWindow(GetDlgItem(hwndMain, IDC_CHECKREAD), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_OPENR), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_OPENW), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_WRITEPATH), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_SAVEPATH), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_SAVE), false);
			}
			else CheckDlgButton(hwndMain,IDC_CHECKREAD,BST_CHECKED);
			return TRUE;
		case WM_COMMAND:
			if ((WORD)wParam == IDC_CHECKREAD){
				if (hWriteFile != INVALID_HANDLE_VALUE) CloseHandle(hWriteFile);
				hWriteFile = INVALID_HANDLE_VALUE;
				SetDlgItemText(hwndMain, IDC_WRITEPATH, "");
				EnableWindow(GetDlgItem(hwndMain, IDC_SAVE), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_SAVEPATH), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_OPENR), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_BTNREAD), GetDlgItemText(hwndMain, IDC_SAVEPATH, (LPSTR)ofnPath, MAX_PATH) != 0);
				EnableWindow(GetDlgItem(hwndMain, IDC_WRITE), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_WRITEPATH), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_OPENW), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_BTNWRITE), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_MODCHAN), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_OVERRIDE), false);
				return TRUE;
			}
			else if ((WORD)wParam == IDC_CHECKWRITE){
				CheckDlgButton(hwndMain, IDC_OVERRIDE, false);
				EnableWindow(GetDlgItem(hwndMain, IDC_SAVE), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_SAVEPATH), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_OPENR), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_BTNREAD), false);
				EnableWindow(GetDlgItem(hwndMain, IDC_WRITE), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_WRITEPATH), true);
				EnableWindow(GetDlgItem(hwndMain, IDC_OPENW), true);
				return TRUE;
			}

			else if ((WORD)wParam == IDC_MODCHAN){
				if (bReadOnly || bWarned == true || MessageBox(hwndMain, "INCORRECT RegDmn VALUE WILL BROKE YOUR CARD!! Do not edit custom value unless you are totally sure! Continue?", "Warning", MB_ICONWARNING | MB_YESNO) == IDYES){
					bWarned = true;
					DialogBoxParam(hInst,MAKEINTRESOURCE(IDD_MODCHAN),hwndMain,DialogProcModchan,NULL);
				}
				return TRUE;
			}

			else if ((WORD)wParam == IDC_BTNREAD || (WORD)wParam == IDC_BTNWRITE){
				if (((WORD)wParam == IDC_BTNREAD && GetDlgItemText(hwndMain, IDC_SAVEPATH, (LPSTR)ofnPath, MAX_PATH) == 0) || ((WORD)wParam == IDC_BTNWRITE && GetDlgItemText(hwndMain, IDC_WRITEPATH, (LPSTR)ofnPath, MAX_PATH) == 0)){
					MessageBox(hwndMain, "Choose path", "Error", MB_ICONERROR);
					return TRUE;
				}

				if ((WORD)wParam == IDC_BTNREAD){
					getDeviceInfo(workDevInstance, GET_DEVICE_MEM_START);
					phyAddr = resMemStart;

					if (!phyAddr) {
						MessageBox(0, "Can't detect device memory range (disabled device?)", "Error", MB_ICONERROR);
						return 1;
					}

					ReadEEPROM(ofn.lpstrFile, eepromLength);
				}
				else if ((WORD)wParam == IDC_BTNWRITE){
					unsigned char* eepromCopy = (unsigned char*)malloc(eepromLength+8);
					*(DWORDLONG*)eepromCopy = phyAddr;
					if (IsDlgButtonChecked(hwndMain, IDC_OVERRIDE) == BST_CHECKED){
						unsigned int checksum = 0;

						*(BYTE*)(patchedEeprom+6) = patchOpCap;
						*(WORD*)(patchedEeprom+8) = patchRegDmn;

						for (int i = 5, j = 0; i >= 0; i--, j++){
							*(BYTE*)(patchedEeprom+12+j) = (BYTE)(patchMAC >> (i*8));
						}

						for (unsigned int i = 0; i < eepromLength/2; i++){
							if (i != 1) checksum ^= *(WORD*)(patchedEeprom+i*2);
						}
						checksum ^= 0xFFFF;

						*(WORD*)(patchedEeprom+2) = (WORD)checksum;

						memcpy(eepromCopy+8, patchedEeprom, eepromLength);
					}
					else {
						memcpy(eepromCopy+8, eeprom, eepromLength);
					}
					if (DeviceIoControl(hDriver, WRITE_EEPROM_CODE, eepromCopy, eepromLength+8, 0, 0, &numOfIO, NULL)){
						MessageBox(hwndMain, "Successfully written", "Done", MB_ICONINFORMATION);
					}
					else if (GetLastError() == ERROR_IO_DEVICE){
						MessageBox(hwndMain, "EEPROM COULD BE DAMAGED!! Please do not close this tool and try to write again!", "ERROR DURING WRITING PROCESS!!", MB_ICONERROR);
					}
					else {
						showErrorMessage("Write error. EEPROM not damaged", "Error", GetLastError());
					}
					free(eepromCopy);
				}
			}
			else if ((WORD)wParam == IDC_OPENR){
				if (GetOpenFileName(&ofn)){
					SetDlgItemText(hwndMain, IDC_SAVEPATH, ofn.lpstrFile);
					EnableWindow(GetDlgItem(hwndMain, IDC_BTNREAD), true);
				}
			}
			else if ((WORD)wParam == IDC_OPENW){
				if (GetOpenFileName(&ofn)) {
					EnableWindow(GetDlgItem(hwndMain, IDC_BTNWRITE), false);
					EnableWindow(GetDlgItem(hwndMain, IDC_OVERRIDE), false);
					EnableWindow(GetDlgItem(hwndMain, IDC_MODCHAN), false);
					SetDlgItemText(hwndMain, IDC_WRITEPATH, "");
					if (hWriteFile != INVALID_HANDLE_VALUE) CloseHandle(hWriteFile);
					hWriteFile = CreateFile(ofn.lpstrFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					if (hWriteFile == INVALID_HANDLE_VALUE){
						showErrorMessage("Can't open or lock file", "Error", GetLastError());
						return TRUE;
					}
					size_t fSize = GetFileSize(hWriteFile, 0);
					if (fSize == 376 || fSize == 727 || fSize == 3256) {
						if (eeprom) free(eeprom);
						if (patchedEeprom) free(patchedEeprom);
						eeprom = (unsigned char*)malloc(fSize);
						patchedEeprom = (unsigned char*)malloc(fSize);
						ReadFile(hWriteFile, eeprom, (DWORD)fSize, &numOfIO, 0);
						if (*(WORD*)(eeprom) != fSize){
							MessageBox(hwndMain, "Invalid EEPROM image", "Error", MB_ICONERROR);
							CloseHandle(hWriteFile);
							hWriteFile = INVALID_HANDLE_VALUE;
						}
						else {
							bool bDumpMatch = fSize == eepromLength;

							if (!bNoCard && !bDumpMatch){
								MessageBox(hwndMain, "Image size doesn't match EEPROM size. You'll be able only to see info in Modes and Channels", "Warning", MB_ICONWARNING);
							}

							unsigned int checksum = 0;

							for (unsigned int i = 0; i < eepromLength/2; i++){
								checksum ^= *(WORD*)(eeprom+i*2);
							}

							if (
								bNoCard
								||
								!bDumpMatch
								||
								checksum == 0xFFFF
								||
								MessageBox(hwndMain, "Invalid checksum. Do you want to fix it and continue?", "Warning", MB_ICONWARNING | MB_YESNO) == IDYES
							){
								if (checksum != 0xFFFF){
									checksum = 0;
									for (unsigned int i = 0; i < eepromLength/2; i++){
										if (i != 1) checksum ^= *(WORD*)(eeprom+8+i*2);
									}
									checksum ^= 0xFFFF;
									*(WORD*)(eeprom+2) = (WORD)checksum;
								}
								memcpy(patchedEeprom, eeprom, eepromLength);
								patchOpCap = *(BYTE*)(eeprom+6);
								patchRegDmn = *(WORD*)(eeprom+8);
								patchMAC = 0;
								for (int i = 0; i < 6; i++){
									patchMAC <<= 8;
									patchMAC += *(BYTE*)(eeprom+12+i);
								}
								//for (int i = 6, j = 0; i >= 0; i--, j++){
									//patchMAC += *(unsigned char*)(eeprom+11+i) << j*8;
								//}
								SetDlgItemText(hwndMain, IDC_WRITEPATH, ofn.lpstrFile);
								if (!bNoCard && bDumpMatch){
									EnableWindow(GetDlgItem(hwndMain, IDC_BTNWRITE), true);
									EnableWindow(GetDlgItem(hwndMain, IDC_OVERRIDE), true);
								}
								else {
									EnableWindow(GetDlgItem(hwndMain, IDC_BTNWRITE), false);
									EnableWindow(GetDlgItem(hwndMain, IDC_OVERRIDE), false);
								}
								EnableWindow(GetDlgItem(hwndMain, IDC_MODCHAN), true);
								bReadOnly = !bDumpMatch;
							}
						}
					}
					else {
						MessageBox(hwndMain, "Invalid image size", "Error", MB_ICONERROR);
						CloseHandle(hWriteFile);
						hWriteFile = INVALID_HANDLE_VALUE;
					}
				}
			}
			else return FALSE;
			return TRUE;
		case WM_CLOSE:
			EndDialog(hwndDlg,TRUE);
			return TRUE;
		case WM_DESTROY:
			PostQuitMessage(0);
			return TRUE;
		default:
			return FALSE;
	}
}

unsigned int getEepromSize() 
{
	unsigned int retVal = 0;
	eeprom = (unsigned char*)malloc(4);
	if (DeviceIoControl(hDriver, GET_SIZE_CODE, &phyAddr, 8, eeprom, 4, &numOfIO, NULL)){
		retVal = *(unsigned int*)eeprom;
	}

	free(eeprom);
	eeprom = 0;
	return retVal;
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(nCmdShow);
	UNREFERENCED_PARAMETER(hPrevInstance);

	HANDLE hMutex = CreateMutex(0, 0, "aet_process_exist");
	if (GetLastError() == ERROR_ALREADY_EXISTS){
		MessageBox(0, "Program already running", "Info", MB_ICONINFORMATION);
		return 0;
	}
	//DialogBoxParam(hInst,MAKEINTRESOURCE(IDD_MODCHAN),0,DialogProcModchan,NULL);
	deviceEnum = (DEVNAME*)calloc(sizeof(DEVNAME),1024);
	getDeviceInfo("PCI\\VEN_168C", ENUM_DEVICES);

	if (LoadDriver())
		bDriverLoaded = true;

	if (devCount == 0){
		MessageBox(0, "No Atheros wireless devices found", "Error", MB_ICONERROR);
		bNoCard = true;
	}
	else if (!bDriverLoaded){
		bNoCard = true;
	}
	else if (devCount != 1){
		DialogBoxParam(hInstance,MAKEINTRESOURCE(IDD_CHOOSE),NULL,DialogProcChoose,NULL);
	}
	else {
		workDevInstance = deviceEnum[0].Instance;
	}

	if (!workDevInstance && !bNoCard) bNoCard = true;

	if (!bNoCard){
		getDeviceInfo(workDevInstance, GET_DEVICE_MEM_START);
		phyAddr = resMemStart;
	}

	if (bNoCard || phyAddr == 0)
	{
		bNoCard = false;
		phyAddr = 0xFBFF0000;
	}

	if (!bNoCard){
		if (!phyAddr) {
			MessageBox(0, "Can't detect device memory range (disabled device?)", "Error", MB_ICONERROR);
			bNoCard = true;
			//return 0;
		}
		else {
			eepromLength = getEepromSize();

			if(eepromLength == 0)
				eepromLength = 376;

			if (!eepromLength){
				MessageBox(0, "Can't detect EEPROM size", "Error", MB_ICONERROR);
				bNoCard = true;
				//return 0;
			}
		}
	}

	if (bNoCard){
		MessageBox(0, "Initialization failed. You'll be able only to see dump info in Modes and Channels", "Warning", MB_ICONWARNING);
	}

	hInst = hInstance;
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = (LPSTR)ofnPath;
	ofn.lpstrFilter = NULL;
	ofn.lpstrCustomFilter = NULL;
	ofn.nMaxCustFilter = NULL;
	ofn.nFilterIndex = 1;
	ofn.nMaxFile = MAX_PATH*2+2;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = NULL;
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrTitle = NULL;
	ofn.Flags = OFN_DONTADDTORECENT;
	ofn.nFileOffset = 0;
	ofn.nFileExtension = NULL;
	ofn.lpstrDefExt = NULL;
	ofn.lCustData = NULL;
	ofn.lpfnHook = NULL;
	ofn.lpTemplateName = NULL;
	ofn.pvReserved = NULL;
	ofn.dwReserved = NULL;
	ofn.FlagsEx = NULL;

	if(!bNoCard && 0 == strcmp(lpCmdLine, "/r512"))
	{
		if(MessageBox(0, "Read raw 512 bytes of EEPROM?", "Warning", MB_ICONWARNING | MB_YESNO) == IDYES)
		{
			ReadEEPROM("eeprom_dump.rom", 512);
		}
	}
	else if(!bNoCard && 0 == strcmp(lpCmdLine, "/w512"))
	{
		if(MessageBox(0, "Write raw 512 bytes of EEPROM?", "Warning", MB_ICONWARNING | MB_YESNO) == IDYES)
		{
			WriteEEPROM("eeprom_dump.rom", 512);
		}
	}
	else if(!bNoCard && 0 == strcmp(lpCmdLine, "/fixcrc"))
	{
		if(MessageBox(0, "Correct checksum of EEPROM?", "Warning", MB_ICONWARNING | MB_YESNO) == IDYES)
		{
			CorrectChecksum(512);
		}
	}
	else
		DialogBoxParam(hInstance,MAKEINTRESOURCE(IDD_MAIN),NULL,DialogProcMain,NULL);


	if (bDriverLoaded) UnloadDriver();
	if (hMutex) CloseHandle(hMutex);
	return 0;
}
