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
                cout << "IP :" << recvbuf << endl;
                iSendResult = send(ClientSocket, "ACK", strlen("ACK"), 0);
                iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
                cout << "MAC :" << recvbuf << endl;
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
