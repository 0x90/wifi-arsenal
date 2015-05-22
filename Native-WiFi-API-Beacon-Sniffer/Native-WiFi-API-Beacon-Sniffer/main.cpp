#include <windows.h>
#include <wlanapi.h>
#include <Shlwapi.h>
#include <stdio.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "Shlwapi.lib")

// Disable 4244 Warning Message for a cleaner output.
#pragma warning(disable : 4244)

BOOL isVistaOrLater();

DWORD sniff(GUID ifaceGuid, char *filename);
DWORD writeData(char *filename, PBYTE data, unsigned int size);

DWORD printWirelessInterfacesList();
DWORD getWirelessInterface(DWORD index, PWLAN_INTERFACE_INFO ifaceInfo);

DWORD getPcapGlobalHeaderData(PBYTE glbHdrData, unsigned int *glbHdrSize);
DWORD getBeaconFromBssEntry(PWLAN_BSS_ENTRY bssEntry, PBYTE beaconFrame, unsigned int *frameSize);
DWORD getPcapPacketHeaderData(unsigned long long timestamp, PBYTE pktHdrData, unsigned int *pktHdrSize, unsigned int pktSize);

int main(int argc, char *argv[])
{
	DWORD result = 0;
	DWORD ifaceIndex = 0;
	PBYTE hdrData = NULL;
	char *outputFilename;
	DWORD numOfIfaces = 0;
	unsigned int hdrSize = 0;
	WLAN_INTERFACE_INFO ifaceInfo;

	if(!isVistaOrLater())
	{
		printf("Error: tool requires Windows Vista or later.");
		return -1;
	}

	if(argc < 2)
	{
		printf("Usage\n");
		printf("\t%s <output filename>\n");
		return -1;
	}

	outputFilename = argv[1];

	if(PathFileExistsA(outputFilename))
	{
		printf("Error: Output filename '%s' already exist.", argv[1]);
		return -1;
	}

	printf("Output filename: %s\n\n", outputFilename);

	printf("Wireless Interfaces:\n\n");
	numOfIfaces = printWirelessInterfacesList();
	if(numOfIfaces == -1)
	{
		printf("Error: Unable to list wireless Interfaces.\n");
		return -1;
	}
	else if(numOfIfaces == 0)
	{
		printf("Error: No wireless Interfaces.\n");
		return -1;
	}

	printf("\nSelect the Wireless Interface to use: ");
	scanf_s("%i", &ifaceIndex);

	if(ifaceIndex > numOfIfaces - 1)
	{
		printf("Error: Invalid Wireless Interface selected.\n");
		return -1;
	}

	ZeroMemory(&ifaceInfo, sizeof(WLAN_INTERFACE_INFO));

	result = getWirelessInterface(ifaceIndex, &ifaceInfo);
	if(result != ERROR_SUCCESS)
	{
		printf("Error: Unable to use the selected Wireless Interface.\n");
		return -1;
	}

	hdrData = (PBYTE)malloc(24);

	result = getPcapGlobalHeaderData(hdrData, &hdrSize);
	if(result != ERROR_SUCCESS)
	{
		printf("Error: Unable to write pcap global headers to file.\n");
		return -1;
	}

	writeData(outputFilename, hdrData, hdrSize);

	free(hdrData);

	printf("\nCtrl+C to stop \"sniffing\"\n");

	while(1)
	{
		result = sniff(ifaceInfo.InterfaceGuid, outputFilename);
	}

	return ERROR_SUCCESS;
}

BOOL isVistaOrLater()
{
	OSVERSIONINFO osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);

	if(osvi.dwMajorVersion < 6)
		return false;

	return true;
}

DWORD sniff(GUID ifaceGuid, char *filename)
{
	DWORD result = 0;
	DWORD dwResult = 0;
	HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;

	PWLAN_BSS_LIST pWlanBssList = NULL;

	dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if(dwResult != ERROR_SUCCESS)
	{
        return -1;
    }

	dwResult = WlanScan(hClient, &ifaceGuid, NULL, NULL, NULL);

	Sleep(1000);

	dwResult = WlanGetNetworkBssList(hClient, &ifaceGuid, NULL, dot11_BSS_type_infrastructure, NULL, NULL, &pWlanBssList);
    if(dwResult != ERROR_SUCCESS)
	{
		WlanCloseHandle(hClient, NULL);
		return -1;
	}

	for (DWORD i = 0; i < pWlanBssList->dwNumberOfItems; i++)
	{
		PWLAN_BSS_ENTRY pWlanBssEntry = &pWlanBssList->wlanBssEntries[i];

		unsigned int frameSize = 0;
		void *beaconFrame = malloc(3000);

		result = getBeaconFromBssEntry(pWlanBssEntry, (PBYTE)beaconFrame, &frameSize);

		if(result == ERROR_SUCCESS)
		{
			unsigned int pktHdrSize = 0;
			void *pktHdrData = malloc(20);
			unsigned long long hostTimestamp = pWlanBssEntry->ullHostTimestamp;

			result = getPcapPacketHeaderData(hostTimestamp, (PBYTE)pktHdrData, &pktHdrSize, frameSize);

			if(result == ERROR_SUCCESS)
			{
				writeData(filename, (PBYTE)pktHdrData, pktHdrSize);
				writeData(filename, (PBYTE)beaconFrame, frameSize);
			}

			free(pktHdrData);
		}

		free(beaconFrame);
	}

	WlanCloseHandle(hClient, NULL);

	return ERROR_SUCCESS;
}

DWORD writeData(char *filename, PBYTE data, unsigned int size)
{
	FILE *fd = NULL;
	 // Append Binary Mode
	fopen_s(&fd, (char*)filename, "ab");
	fwrite(data, sizeof(char), size, fd);
	fclose(fd);
	return ERROR_SUCCESS;
}

DWORD printWirelessInterfacesList()
{
	DWORD dwResult = 0;
	HANDLE hClient = NULL;
	DWORD numOfIfaces = 0;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    
    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if(dwResult != ERROR_SUCCESS)
	{
        return -1;
    }
    
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if(dwResult != ERROR_SUCCESS)
	{
		WlanCloseHandle(hClient, NULL);
        return -1;
    }
    else
	{
		numOfIfaces = pIfList->dwNumberOfItems;

		for(DWORD i = 0; i < pIfList->dwNumberOfItems; i++)
		{
			pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[i];
			wprintf(L"\t[%d] - %s\n", i, pIfInfo->strInterfaceDescription);
		}
    }

    if(pIfList != NULL)
	{
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }

	WlanCloseHandle(hClient, NULL);

    return numOfIfaces;
}

DWORD getWirelessInterface(DWORD index, PWLAN_INTERFACE_INFO ifaceInfo)
{
	DWORD dwResult = 0;
	HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    
    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if(dwResult != ERROR_SUCCESS)
	{
        return -1;
    }
    
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if(dwResult != ERROR_SUCCESS)
	{
		WlanCloseHandle(hClient, NULL);
        return -1;
    }
    else
	{
		if(pIfList->dwNumberOfItems >= index)
		{
			pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[index];
			memcpy(ifaceInfo, pIfInfo, sizeof(WLAN_INTERFACE_INFO));
		}
    }

    if(pIfList != NULL)
	{
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }

	WlanCloseHandle(hClient, NULL);

	if(pIfInfo == NULL)
		return -1;

    return ERROR_SUCCESS;
}

DWORD getPcapGlobalHeaderData(PBYTE glbHdrData, unsigned int *glbHdrSize)
{
	unsigned int index = 0;

	// Magic Number
	glbHdrData[index++] = 0xd4;
	glbHdrData[index++] = 0xc3;
	glbHdrData[index++] = 0xb2;
	glbHdrData[index++] = 0xa1;
	// Major version number -> 2
	glbHdrData[index++] = 0x02;
	glbHdrData[index++] = 0x00;
	// Minor version number -> 4
	glbHdrData[index++] = 0x04;
	glbHdrData[index++] = 0x00;
	// GMT to local correction -> 0
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	// Accuracy of timestamps -> 0
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	// Max length of captured packets, in octets -> 65535
	glbHdrData[index++] = 0xff;
	glbHdrData[index++] = 0xff;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	// Data link type -> 105 (802.11)
	glbHdrData[index++] = 0x69;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;
	glbHdrData[index++] = 0x00;

	*glbHdrSize = index;

	return ERROR_SUCCESS;
}

DWORD getBeaconFromBssEntry(PWLAN_BSS_ENTRY bssEntry, PBYTE beaconFrame, unsigned int *frameSize)
{
	unsigned int index = 0;

	beaconFrame[index++] = 0x80; // Type Managment - Subtype Beacon
	beaconFrame[index++] = 0x00; // Flags
	// Duration
	beaconFrame[index++] = 0x00;
	beaconFrame[index++] = 0x00;
	// Destination Address
	beaconFrame[index++] = 0xff; beaconFrame[index++] = 0xff;
	beaconFrame[index++] = 0xff; beaconFrame[index++] = 0xff;
	beaconFrame[index++] = 0xff; beaconFrame[index++] = 0xff;
	// Source Address
	// DOT11_MAC_ADDRESS bssid = bssEntry->dot11Bssid;
	beaconFrame[index++] = bssEntry->dot11Bssid[0]; beaconFrame[index++] = bssEntry->dot11Bssid[1];
	beaconFrame[index++] = bssEntry->dot11Bssid[2]; beaconFrame[index++] = bssEntry->dot11Bssid[3];
	beaconFrame[index++] = bssEntry->dot11Bssid[4]; beaconFrame[index++] = bssEntry->dot11Bssid[5];
	// Bssid Address
	beaconFrame[index++] = bssEntry->dot11Bssid[0]; beaconFrame[index++] = bssEntry->dot11Bssid[1];
	beaconFrame[index++] = bssEntry->dot11Bssid[2]; beaconFrame[index++] = bssEntry->dot11Bssid[3];
	beaconFrame[index++] = bssEntry->dot11Bssid[4]; beaconFrame[index++] = bssEntry->dot11Bssid[5];
	// Fragment and Sequence Number set to Zero - Unable to get the following two bytes.
	beaconFrame[index++] = 0x00;
	beaconFrame[index++] = 0x00;
	// Timestamp
	ULONGLONG timestamp = bssEntry->ullTimestamp;
	beaconFrame[index++] = timestamp;
	beaconFrame[index++] = timestamp >>  8;
	beaconFrame[index++] = timestamp >> 16;
	beaconFrame[index++] = timestamp >> 24;
	beaconFrame[index++] = timestamp >> 32;
	beaconFrame[index++] = timestamp >> 40;
	beaconFrame[index++] = timestamp >> 48;
	beaconFrame[index++] = timestamp >> 56;
	// Interval
	unsigned short interval = bssEntry->usBeaconPeriod;
	beaconFrame[index++] = interval;
	beaconFrame[index++] = interval >> 8;
	// Capabilities
	unsigned short capabilities = bssEntry->usCapabilityInformation;
	beaconFrame[index++] = capabilities;
	beaconFrame[index++] = capabilities >> 8;

	// Information Elements
	PBYTE pIeRawData = (PBYTE)bssEntry + bssEntry->ulIeOffset;
	PBYTE pBeaconFrame = (PBYTE)&beaconFrame[index];
	memcpy((void *)pBeaconFrame, (void *)pIeRawData, bssEntry->ulIeSize);
	index += bssEntry->ulIeSize;

	*frameSize = index;

	return 0;
}

DWORD getPcapPacketHeaderData(unsigned long long timestamp, PBYTE pktHdrData, unsigned int *pktHdrSize, unsigned int pktSize)
{
	// TODO: Use real host timestamp
	unsigned int index = 0;
	
	// Timestamp seconds
	pktHdrData[index++] = 0;
	pktHdrData[index++] = 0;
	pktHdrData[index++] = 0;
	pktHdrData[index++] = 0;
	// Timestamp microseconds
	pktHdrData[index++] = 0;
	pktHdrData[index++] = 0;
	pktHdrData[index++] = 0;
	pktHdrData[index++] = 0;
	// Number of octets of packet saved in file
	pktHdrData[index++] = pktSize;
	pktHdrData[index++] = pktSize >>  8;
	pktHdrData[index++] = pktSize >> 16;
	pktHdrData[index++] = pktSize >> 24;
	// Actual length of packet
	pktHdrData[index++] = pktSize;
	pktHdrData[index++] = pktSize >>  8;
	pktHdrData[index++] = pktSize >> 16;
	pktHdrData[index++] = pktSize >> 24;

	*pktHdrSize = index;

	return ERROR_SUCCESS;
}
