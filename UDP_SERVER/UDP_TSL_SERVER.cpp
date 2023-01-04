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
#include <openssl/bio.h>
#include <openssl/bioerr.h>
#include <openssl/ssl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main()
{

	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		
	}

	// Initialize OpenSSL
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		// Handle error
		// ...
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(1711);
	ret = bind(sock, (sockaddr*)&addr, sizeof(addr));
	if (ret == SOCKET_ERROR) {
		// Handle error
		// ...
	}

	BIO* bio = BIO_new_dgram(AF_INET, BIO_NOCLOSE);
	if (!bio) {
		// Error creating DTLS BIO
		return -1;
	}
	SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());

	if (SSL_CTX_use_certificate_file(ctx, "C:\\Users\\filip\\source\\repos\\UDP_TSL_SERVER\\my.pem", SSL_FILETYPE_PEM) <= 0) {
	
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "C:\\Users\\filip\\source\\repos\\UDP_TSL_SERVER\\my-pass.pem", SSL_FILETYPE_PEM) <= 0) {
		
		exit(EXIT_FAILURE);
	}

	SSL* ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);


	// Set up the WSAPOLLFD structure for the socket
	WSAPOLLFD fds[1];
	fds[0].fd = sock;
	fds[0].events = POLLIN;

	// Open the file for writing
	FILE* file = fopen("plik.txt", "wb");
	if (file == NULL) {
		// Error opening file
		return -1;
	}
	char buffer[1024];
	int numEvents;
	int timeout = 1000; // 1 second timeout

	while (true) {

		numEvents = WSAPoll(fds, 1, -1);
		if (numEvents == SOCKET_ERROR) {
			cout << "Error in WSAPoll" << endl;
			return -1;
		}
		if (numEvents == 0) {
			// Timeout expired
			continue;
		}
		if (fds[0].revents & POLLIN) {
			// DTLS BIO has data available
			int len = SSL_read(ssl, buffer, sizeof(buffer));
			if (len <= 0) {
				// Error reading from DTLS BIO or end of file
				break;
			}
			cout << "Recv data: " << len << " bytes";
			fwrite(buffer, 1, len, file);
		}

	}

	// Close the DTLS BIO and file, and clean up the OpenSSL library
	BIO_free(bio);
	fclose(file);
	CRYPTO_cleanup_all_ex_data();

	return 0;
}
