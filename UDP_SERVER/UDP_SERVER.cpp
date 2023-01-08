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

#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")


#define PORT 12345
#define HOST "127.0.0.1"
#define MAX_CLIENTS 5
#define MAX_MESSAGE_LENGTH 1024

using namespace std;

// Struktura danych przechowująca informacje o połączeniu z klientem
typedef struct {
	SOCKET socket; // Gniazdo połączenia
	SSL* ssl; // Kontekst szyfrowania SSL
	char message[MAX_MESSAGE_LENGTH]; // Bufor na wiadomość odebraną od klienta
	int message_length; // Długość odebranej wiadomości
} Client;

// Tablica przechowująca informacje o połączonych klientach
Client clients[MAX_CLIENTS];

// Liczba połączonych klientów
int client_count = 0;

int main(int argc, char* argv[]) {
	WSADATA wsa_data;
	SOCKET server_socket;
	struct sockaddr_in server_address;
	SSL_CTX* ssl_context;
	SSL* ssl;

	// Inicjalizacja biblioteki WinSock
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}

	// Inicjalizacja kontekstu szyfrowania SSL
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	ssl_context = SSL_CTX_new(DTLS_server_method());
	if (ssl_context == NULL) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return 1;
	}
	if (SSL_CTX_use_certificate_file(ssl_context, "cert.crt", SSL_FILETYPE_PEM) <= 0) {

		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_context, "cert.key", SSL_FILETYPE_PEM) <= 0) {

		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(ssl_context))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}

	// Tworzenie gniazda serwera
	server_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (server_socket == INVALID_SOCKET) {
		fprintf(stderr, "socket failed\n");
		return 1;
	}

	// Konfiguracja adresu serwera
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(HOST);
	server_address.sin_port = htons(PORT);

	// Powiązanie gniazda serwera z adresem
	if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
		fprintf(stderr, "bind failed\n");
		return 1;
	}

	while (1) {
		// Tablica struktur pollfd do przekazania do funkcji poll
		struct pollfd fds[MAX_CLIENTS + 1];
		// Bufor na adres klienta
		struct sockaddr_in client_address;
		int client_address_length = sizeof(client_address);
		// Bufor na wiadomość odebraną od klienta
		char message[MAX_MESSAGE_LENGTH];
		int message_length;
		int i;

		// Konfiguracja struktur pollfd
		memset(fds, 0, sizeof(fds));
		fds[0].fd = server_socket;
		fds[0].events = POLLIN;
		for (i = 0; i < client_count; i++) {
			fds[i + 1].fd = clients[i].socket;
			fds[i + 1].events = POLLIN;
		}

		// Oczekiwanie na dane do odczytu lub nowe połączenie
		if (WSAPoll(fds, client_count + 1, -1) < 0) {
			fprintf(stderr, "poll failed\n");
			break;
		}

		// Sprawdzanie, czy dane są dostępne do odczytu
		if (fds[0].revents & POLLIN) {
			// Odbieranie wiadomości od nowego klienta
			message_length = recvfrom(server_socket, message, sizeof(message), 0, (struct sockaddr*)&client_address, &client_address_length);
			if (message_length < 0) {
				fprintf(stderr, "recvfrom failed\n");
				continue;
			}

			//TODO: Dodanie sprawdzania czy user juz sie laczyl

			message[message_length] = '\0';
			printf("Recieved: %s\n", message);


			// Dodawanie nowego klienta
			if (client_count < MAX_CLIENTS) {
				// Tworzenie nowego gniazda połączenia
				SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, 0);
				if (client_socket == INVALID_SOCKET) {
					fprintf(stderr, "socket failed\n");
					continue;
				}

				// Konfiguracja adresu klienta
				memset(&client_address, 0, sizeof(client_address));
				client_address.sin_family = AF_INET;
				client_address.sin_addr.s_addr = htonl(INADDR_ANY);
				client_address.sin_port = htons(0);

				// Powiązanie gniazda z adresem klienta
				if (bind(client_socket, (struct sockaddr*)&client_address, sizeof(client_address)) == SOCKET_ERROR) {
					fprintf(stderr, "bind failed\n");
					closesocket(client_socket);
					continue;
				}

				// Tworzenie kontekstu szyfrowania SSL dla połączenia z klientem
				ssl = SSL_new(ssl_context);
				if (ssl == NULL) {
					fprintf(stderr, "SSL_new failed\n");
					continue;
				}

				// Powiązanie gniazda z kontekstem szyfrowania SSL
				if (!SSL_set_fd(ssl, client_socket)) {
					fprintf(stderr, "SSL_set_fd failed\n");
					SSL_free(ssl);
					continue;
				}



				// Dodawanie klienta do tablicy
				clients[client_count].socket = client_socket;
				clients[client_count].ssl = ssl;
				client_count++;
			}
		}

	}

	// Zamykanie gniazd i kontekstów szyfrowania
	for (int i = 0; i < client_count; i++) {
		SSL_free(clients[i].ssl);
		closesocket(clients[i].socket);
	}
	SSL_CTX_free(ssl_context);
	closesocket(server_socket);

	// Zwalnianie biblioteki WinSock
	WSACleanup();

	return 0;
}
