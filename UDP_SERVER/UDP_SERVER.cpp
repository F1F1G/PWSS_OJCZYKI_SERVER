#define _WINSOCK_DEPRECATED_NO_WARNINGS
#undef UNICODE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define ROZMIAR 20
#define _XOPEN_SOURCE_EXTENDED 1
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <filesystem>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string>
#include <io.h>
#include <map>
#include <vector>
#include <iterator>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")

using namespace std;


int main()
{
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    // SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
    if (ctx == NULL) {
        cerr << "Error creating DTLS context" << endl;
        return 1;
    }
   /* if (SSL_CTX_use_certificate_file(ctx, "C:\\Users\\mrojo\\Desktop\\STUDIA\\UDP\\Server\\Server\\my.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "C:\\Users\\mrojo\\Desktop\\STUDIA\\UDP\\Server\\Server\\my-pass.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    */
    WSADATA wsaData;
    // inicjalizacja żądanej wersja biblioteki WinSock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }
    int const maxSize = 1024;
    char dane[maxSize];
    memset(dane, 0, maxSize);
    FILE* plik;
    int count = 0;
    unsigned short port = 1711; // Ustawienie portu
    struct sockaddr_in sa;
    struct sockaddr_in sk;
    sa.sin_port = ntohs(port); // Konwersja portu na postać sieciową
    sa.sin_family = AF_INET; // Ustawienie adresu IP na format IPv4
    if (inet_pton(AF_INET, "127.0.0.1", &(sa.sin_addr)) <= 0)  // Inicjalizacja struktury
    {
        printf("Nieprawidlowy adres \n");
        return -1;
    }
    int socketK = socket(sa.sin_family, SOCK_DGRAM, 0); // Stworzenie gniazda dla Klienta

    if (socketK < 0) // Kontrola błędu
    {
        cout << "Błąd podczas tworzenia socketu!" << endl;
        WSACleanup(); //na koniec programu zwalniamy interfejs
        return 1;
    }

    if (bind(socketK, (struct sockaddr*)&sa, sizeof(sa)) > 0)
    {
        cout << "Błąd podczas przypisywania gniazda!" << endl;
        closesocket(socketK);
        WSACleanup(); // zwalniamy interfejs
        return 1;
    }

    /* if (listen(socketK, 5) < 0)
     {
         cout << "Błąd podczas sluchania" << endl;
         closesocket(socketK);
         WSACleanup(); // zwalniamy interfejs
         return 1;
     }
     else */ {

        cout << "serwer czeka na pol`aczenie" << endl;
    }
     //accept the dtls connection 


     //SSL_set_accept_state(ssl);
     //SSL_set_fd(ssl, socketK);
    /* int ret = SSL_accept(ssl);
     if (ret < 0) {
         cout << "Error" << endl;
         SSL_shutdown(ssl);
         SSL_free(ssl);
         closesocket(socketK);
         SSL_CTX_free(ctx);
         WSACleanup(); // zwalniamy interfejs
         return 1;
     }*/

     //struct pollfd ;
     struct pollfd pollfd[1];
     memset(&pollfd, 0, sizeof(pollfd));
     pollfd[0].fd = socketK;
     pollfd[0].events = POLLRDNORM;
     pollfd[0].revents = 0;
     //int sockets;


     socklen_t ska = sizeof(sk);
     char bufor[INET_ADDRSTRLEN];
     string path;
     int rslt;
     int resultd = 0;
     int ssa = sizeof(sa);
     int total = 0;
     while (true) {
         if (rslt = WSAPoll(pollfd, 1, INFINITE) > 0) {
             inet_ntop(AF_INET, &(sk.sin_addr), bufor, INET_ADDRSTRLEN);
             string fN = string(bufor) + string("-" + string(".bin"));
             plik = fopen(fN.c_str(), "wb");
             if (plik == NULL) {
                 cout << "Error opening file" << endl;
                 return 1;
             }

             else {
                 if (pollfd[0].revents & POLLRDNORM) {
                     SSL* ssl = SSL_new(ctx);
                     BIO* bio = BIO_new_dgram(socketK, BIO_NOCLOSE);
                     SSL_set_bio(ssl, bio, bio);


                     do {

                         //resultd = 0;
                   //  resultd = recvfrom(pollfd.fd, dane, maxSize, 0, (struct sockaddr*)&sk, &ska);
                         resultd = SSL_read(ssl, dane, sizeof(dane));
                         if (resultd == SOCKET_ERROR) {
                             //  close(plik)
                             fclose(plik);
                         }
                         else if (strcmp(dane, "NOFILE") == 0) {
                             cout << "File doesnt exist on server" << endl;
                         }
                         else if (strcmp(dane, "QUIT") == 0) {
                             cout << "Transmission ended" << endl;
                         }
                         else {
                             cout << "data upload" << endl;
                             fwrite(dane, sizeof(char), resultd, plik);
                         }
                         //  memset(dane, 0, maxSize);

                     } while (resultd == maxSize);
                 }
                 else {
                     cout << "Revent" << endl;
                 }
                 fclose(plik);
             }
         }
     }
     closesocket(socketK);
     WSACleanup();
}

