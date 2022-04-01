#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream> //std::stringstream

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

#include <stdio.h>
#include <Windows.h>
#include <Iphlpapi.h>
#include <Assert.h>
#pragma comment(lib, "iphlpapi.lib")

struct tuple1
{
    char *ipAddress;
    char *macAddress;
};

tuple1 getMAC()
{
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
    char *mac_addr = (char *)malloc(18);
    char *ipAddress = (char *)malloc(15);
    tuple1 returnValues = {NULL, NULL};

    AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (AdapterInfo == NULL)
    {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        free(mac_addr);
        return returnValues; // it is safe to call free(NULL)
    }

    // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(AdapterInfo);
        AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
        if (AdapterInfo == NULL)
        {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            free(mac_addr);
            return returnValues;
        }
    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR)
    {
        // Contains pointer to current adapter info
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        do
        {
            // technically should look at pAdapterInfo->AddressLength
            //   and not assume it is 6.
            sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
                    pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                    pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                    pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
            printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);

            //pulls IPs
            sprintf(ipAddress, "%d.%d.%d.%d",
                    pAdapterInfo->IpAddressList.IpAddress.String[0], pAdapterInfo->IpAddressList.IpAddress.String[1],
                    pAdapterInfo->IpAddressList.IpAddress.String[2], pAdapterInfo->IpAddressList.IpAddress.String[3]);
            printf("Address: %s, mac: %s\n", ipAddress, mac_addr);

            // print them all, return the last one.
            // return mac_addr;

            printf("\n");

            pAdapterInfo = pAdapterInfo->Next;
            returnValues = {ipAddress, mac_addr};
        } while (pAdapterInfo);
    }
    free(AdapterInfo);
    return returnValues; // caller must free.
}

using namespace std;

string PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                      PROCESS_VM_READ,
                                  FALSE, processID);

    // Get the process name.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                               &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                              sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    // Print the process name and identifier.

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    // Release the handle to the process.
    stringstream s;
    s << "" << szProcessName << " PID:" << processID << endl;
    ;
    CloseHandle(hProcess);
    return s.str();
}

int __cdecl main(int argc, char **argv)
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
    //
    //
    //These are the bytes being sent
    const char *sendbuf = "What if we chnage this what does it do";
    //
    //
    //

    tuple1 information = getMAC();
    printf(information.ipAddress);
    printf("\n");
    printf(information.macAddress);
    cout << endl;

    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result);
    if (iResult != 0)
    {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                               ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET)
        {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET)
    {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    //
    //
    //
    while (true)
    {
        cout << "\t----------Waiting for instructions---------------" << endl;

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        string rc = string(recvbuf);
        if (rc.find("1") != std::string::npos)
        {

            cout << "Sending the information" << endl;
            cout << information.ipAddress << "..." << endl;
            iResult = send(ConnectSocket, information.ipAddress, strlen(information.ipAddress), 0);
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);

            cout << information.macAddress << "..." << endl;
            iResult = send(ConnectSocket, information.macAddress, strlen(information.macAddress), 0);
        }
        else if (rc.find("2") != std::string::npos)
        {

            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
            recvbuf[iResult] = 0;
            cout << "Server requested for file : " << recvbuf << endl;
            ifstream myfile(recvbuf);
            if (myfile.is_open())
            {
                iResult = send(ConnectSocket, "1", strlen("1"), 0);
                myfile.close();
                FILE *f = fopen(recvbuf, "rb");
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                fseek(f, 0, SEEK_SET);
                char *content = (char *)malloc(fsize + 1);
                fread(content, fsize, 1, f);
                fclose(f);
                iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
                iResult = send(ConnectSocket, to_string(fsize).c_str(), strlen(to_string(fsize).c_str()), 0);
                iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
                iResult = send(ConnectSocket, content, fsize, 0);
                cout << "File sent" << endl;
            }
            else
            {
                iResult = send(ConnectSocket, "2", strlen("2"), 0);
                cout << "failed to open the file" << endl;
            }
        }
        else if (rc.find("3") != std::string::npos)
        {
            cout << "Running processes requested" << endl;
            DWORD aProcesses[1024], cbNeeded, cProcesses;
            unsigned int i;

            if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
            {
                iResult = send(ConnectSocket, "2", strlen("2"), 0);
                cout << "Failted to get the pocesses" << endl;
                continue;
            }
            else
            {
                iResult = send(ConnectSocket, "1", strlen("1"), 0);
                cout << "Getting all the running processess" << endl;
            }
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);

            // Calculate how many process identifiers were returned.

            cProcesses = cbNeeded / sizeof(DWORD);

            // Print the name and process identifier for each process.
            string data = "";
            for (i = 0; i < cProcesses; i++)
            {
                if (aProcesses[i] != 0)
                {
                    data += PrintProcessNameAndID(aProcesses[i]);
                }
            }
            iResult = send(ConnectSocket, to_string(data.length()).c_str(), strlen(to_string(data.length()).c_str()), 0);
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
            string temp = "";
            int templn = recvbuflen-16;
            int ie = 0;
            while (ie < data.length())
            {
                if(ie+templn>data.length()){
                    temp = data.substr(ie);
                }{
                    temp = data.substr(ie, templn);
                }
                
                ie += templn;
                // cout<<temp<<"--------------------"<<endl;
                // cout<<ie<<"/"<<data.length()<<"--"<<strlen(data.c_str())<<endl;
                iResult = send(ConnectSocket, temp.c_str(), temp.length(), 0);
                iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);

            }
        }
        else if (rc.find("4") != std::string::npos)
        {
            cout << "Quiting" << endl;
            break;
        }
        else
        {

            cout << "Wrong choice, please input 1, 2 or 3 on server" << endl;
        }
    }

    //
    //
    //

    printf("Bytes Sent: %ld\n", iResult);

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}
