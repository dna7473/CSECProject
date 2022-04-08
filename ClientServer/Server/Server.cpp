#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>
// Need to link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
using namespace std;

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
    std::string ret;
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

std::string decryption(char cipher[512])
{
    string decrypted;
    string q = ":&";
    char buff[1024];
    string decryptedString;
    decrypted = XOR(cipher, q);
    char decrypt[1024];
    decryptedString = decrypted.substr(0, decrypted.find("=")) + "=";
    strcpy(buff, decryptedString.c_str());
    strcpy(decrypt, decryptedString.c_str());
    decrypted = base64_decode(decrypt);
    return decrypted;
}

string convertToString(char* a)
{
    string s(a);

    return s;
}

int main(void)
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0)
    {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR)
    {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    cout << "Waiting for client" << endl;
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET)
    {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    else
    {
        printf("Client connected %d\n");
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    do
    {
        string choise;
        string decryptedString1;
        string decryptedString2;
        while (true)
        {
            cout << "\t---------------Menu------------------" << endl;
            cout << "1. Tell the client to send its information" << endl;
            cout << "2. Tell the client to send a file" << endl;
            cout << "3. tell the client to send current running process" << endl;
            cout << "4. Quit" << endl;
            cout << "Input choice: ";
            cin >> choise;
            if (choise.find("1") != std::string::npos)
            {
                string t = "1";
                iSendResult = send(ClientSocket, t.c_str(), t.length(), 0);
                iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                decryptedString1 = decryption(recvbuf);
                cout << "IP :" << decryptedString1 << endl;
                iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                decryptedString2 = convertToString(recvbuf);
                decryptedString2 = decryption(recvbuf);
                cout << "MAC :" << decryptedString2 << endl;
                memset(recvbuf, 0, sizeof recvbuf);
            }
            else if (choise.find("2") != std::string::npos)
            {

                string t = "2";
                iSendResult = send(ClientSocket, t.c_str(), t.length(), 0);
                cout << "Input file name: ";
                cin >> choise;
                cout<<choise;
                iSendResult = send(ClientSocket, choise.c_str(), choise.length(), 0);
                iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                if (string(recvbuf).find("1") != std::string::npos)
                {
                    ofstream myfile;
                    myfile.open(choise.c_str());
                    cout<<"File size1: "<<recvbuf<<endl;
                    iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                    int len=atoi(recvbuf);
                    iResult=0;
                    cout<<"File size: "<<recvbuf<<endl;
                    iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                    while (true)
                    {

                        iResult+= recv(ClientSocket, recvbuf, recvbuflen, 0);
                        cout<<iResult<<"/"<<len<<endl;
                        myfile<<recvbuf;
                        if (iResult>=len )
                        {
                            cout << "Done! file received. " << endl;
                            break;
                        }
                       
                    }
                    myfile.close();
                    memset(recvbuf, 0, sizeof recvbuf);
                }
                else
                {
                    cout << "Client failed to open that file" << endl;
                }
            }
            else if (choise.find("3") != std::string::npos)
            {
                string t = "3";
                iSendResult = send(ClientSocket, t.c_str(), t.length(), 0);
                 iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                  if (string(recvbuf).find("1") != std::string::npos)
                {
                    iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                    int len=atoi(recvbuf);
                    iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                       iResult=0; 
                    while (true)
                    {

                        iResult+= recv(ClientSocket, recvbuf, recvbuflen, 0);
                        iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                        // cout<<iResult<<"/"<<len<<endl;
                        if (iResult>=len )
                        {
                            cout << "Done! All running processes printed on client. " << endl;
                            break;
                        }
                       
                    }
                    memset(recvbuf, 0, sizeof recvbuf);

                }else{
                    cout<<"Failed to get the running processes from the client!"<<endl;
                }

            }
            else if (choise.find("4") != std::string::npos)
            {
                string t = "4";
                iSendResult = send(ClientSocket, t.c_str(), t.length(), 0);
                cout<<"Quiting"<<endl;
                break;
            }
            else
            {
                cout << "Wrong choice, please input 1, 2 or 3" << endl;
            }
        }
        break;
    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}
