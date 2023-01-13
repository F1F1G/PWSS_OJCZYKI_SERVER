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
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <srv.h>

#define PORT 12345
#define HOST "127.0.0.1"
#define MAX_CLIENTS 5
#define MAX_MESSAGE_LENGTH 1024

#define COOKIE_LEN  20

int handleRecievedCommand(char* message, int message_length, int* seq_num, int* operation, FILE* client_file);

static int cookie_gen(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
	unsigned int i;

	for (i = 0; i < COOKIE_LEN; i++, cookie++) {
		*cookie = i;
	}
	*cookie_len = COOKIE_LEN;

	return 1;
}

static int cookie_verify(SSL* ssl, const unsigned char* cookie,
	unsigned int cookie_len)
{
	unsigned int i;

	if (cookie_len != COOKIE_LEN)
		return 0;

	for (i = 0; i < COOKIE_LEN; i++, cookie++) {
		if (*cookie != i)
			return 0;
	}

	return 1;
}

int main(int argc, char** argv) {

	WSADATA wsa_data;
	// Inicjalizacja biblioteki WinSock
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}
	SSL_CTX* ssl_context;
	SSL* ssl;
	BIO* bio;
	BIO_ADDR* peer = BIO_ADDR_new();
	int server_socket;
	struct sockaddr_in server_address, client_addr;
	BIO_ADDR* client_bio_addr = BIO_ADDR_new();
	int client_len;

	// Tablica struktur pollfd do przekazania do funkcji poll
	struct pollfd fds[MAX_CLIENTS + 1];
	int num_clients = 0;
	SSL* client_ssl[MAX_CLIENTS];
	FILE* client_files[MAX_CLIENTS];
	int operations[MAX_CLIENTS];
	struct sockaddr_in client_addrs[MAX_CLIENTS];
	int sequence_numbers[MAX_CLIENTS];
	// Bufor na adres klienta
	struct sockaddr_in client_address;
	int client_address_length = sizeof(client_address);
	// Bufor na wiadomość odebraną od klienta
	char message[MAX_MESSAGE_LENGTH];
	int message_length;
	int i;


	// Initialize SSL library
	SSL_library_init();
	SSL_load_error_strings();

	// Create SSL context
	ssl_context = SSL_CTX_new(DTLSv1_server_method());
	if (ssl_context == NULL) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		WSACleanup();
		return 1;
	}
	if (SSL_CTX_use_certificate_file(ssl_context, "cert.crt", SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_context);
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_context, "cert.key", SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_context);
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(ssl_context))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		SSL_CTX_free(ssl_context);
		WSACleanup();
		exit(EXIT_FAILURE);
	}


	SSL_CTX_set_read_ahead(ssl_context, 1);
	SSL_CTX_set_cookie_generate_cb(ssl_context, cookie_gen);
	SSL_CTX_set_cookie_verify_cb(ssl_context, cookie_verify);

	// Tworzenie gniazda serwera
	server_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (server_socket == INVALID_SOCKET) {
		fprintf(stderr, "socket failed\n");
		SSL_CTX_free(ssl_context);
		WSACleanup();
		return 1;
	}

	// Konfiguracja adresu serwera
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(HOST);
	server_address.sin_port = htons(PORT);


	// Powiązanie gniazda serwera z adresem
	if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
		fprintf(stderr, "bind failed\n");
		SSL_CTX_free(ssl_context);
		closesocket(server_socket);

		WSACleanup();
		return 1;
	}

	fds[0].fd = server_socket;
	fds[0].events = POLLIN;



	while (1) {
		int res = WSAPoll(fds, num_clients + 1, 100) < 0;
		// Oczekiwanie na dane do odczytu lub nowe połączenie
		if (res < 0) {
			fprintf(stderr, "poll failed\n");
			break;
		}
		if (res == 0) {
			// Timeout expired
			int i;
			for (i = 1; i <= num_clients; i++) {
					printf("Client %d disconnected\n", i - 1);
					SSL_shutdown(client_ssl[i - 1]);
					SSL_free(client_ssl[i - 1]);
					fclose(client_files[i - 1]);
					client_files[i - 1] = NULL;
					sequence_numbers[i - 1] = 0;
					operations[i - 1] = 0;
					num_clients--;
					client_addrs[i - 1] = client_addrs[num_clients];
					client_ssl[i - 1] = client_ssl[num_clients];
					client_files[i - 1] = client_files[num_clients];
					sequence_numbers[i - 1] = sequence_numbers[num_clients];
					operations[i - 1] = operations[num_clients];
					fds[i] = fds[num_clients + 1];
			}
		}
		// Sprawdzanie, czy dane są dostępne do odczytu
		if (fds[0].revents & POLLIN) {

			bio = BIO_new_dgram(server_socket, BIO_NOCLOSE);


			struct timeval timeout;
			timeout.tv_sec = 10;
			timeout.tv_usec = 0;
			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);


			ssl = SSL_new(ssl_context);
			SSL_set_bio(ssl, bio, bio);
			SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);


			while (DTLSv1_listen(ssl, (BIO_ADDR*)&client_address) <= 0) {
				continue;
			}
			int client_fd = socket(AF_INET6, SOCK_DGRAM, 0);
			bind(client_fd, (struct sockaddr*)&server_address, sizeof(server_address));
			connect(client_fd, (struct sockaddr*)&client_addr, sizeof(client_addr));


			fds[1].fd = client_fd;
			fds[1].events = POLLRDNORM;

			// Odbieranie wiadomości od nowego klienta
			message_length = SSL_read(ssl, message, sizeof(message));
			if (message_length < 0) {
				fprintf(stderr, "recvfrom failed\n");
				continue;
			}

			int i;
			for (i = 0; i < num_clients; i++) {
				if (memcmp(&client_address, &client_addrs[i], sizeof(client_address)) == 0) {
					break;
				}
			}

			if (i == num_clients)
				if (num_clients < MAX_CLIENTS) {
					fds[num_clients + 1].fd = server_socket;
					fds[num_clients + 1].events = POLLIN;
					sequence_numbers[num_clients] = 0;
					operations[num_clients] = 0; // Brak operacji
					char file_name[64];
					sprintf(file_name, "client_%d.txt", i);
					client_files[i] = fopen(file_name, "w");
					if (client_files[i] == NULL) {
						perror("fopen");
						break;
					}

					client_addrs[num_clients] = client_address;
					client_ssl[num_clients] = SSL_new(ssl_context);
					if (client_ssl[num_clients] == NULL) {
						printf("Error: %s", stderr);
						break;
					}
					SSL_set_fd(client_ssl[num_clients], server_socket);
					num_clients++;
				}
				else {
					printf("Cannot accept new client: too many clients already connected\n");
				}
			int command = handleRecievedCommand(message, message_length, &sequence_numbers[i], &operations[i], client_files[i]);
			if (command == -1) {
				printf("Client %d disconnected\n", i);
				SSL_shutdown(client_ssl[i]);
				SSL_free(client_ssl[i]);
				fclose(client_files[i]);
				client_files[i] = NULL;
				sequence_numbers[i] = 0;
				operations[i] = 0;
				num_clients--;
				client_addrs[i] = client_addrs[num_clients];
				client_ssl[i] = client_ssl[num_clients];
				client_files[i] = client_files[num_clients];
				sequence_numbers[i] = sequence_numbers[num_clients];
				operations[i] = operations[num_clients];
				fds[i + 1] = fds[num_clients + 1];
			}
			else if (command == 1) {
				FILE* file = fopen("plik.txt", "rb");
				if (file == NULL) {
					perror("Nie udało się otworzyć pliku");
					break;
				}
				int n;
				char temp[MAX_MESSAGE_LENGTH];
				int seq_num = 0;
				while ((n = fread(message, 1, MAX_MESSAGE_LENGTH, file)) > 0) {
					message[n] = '\0';
					strncpy(temp, message, strlen(message));
					temp[strlen(message)] = '\0';
					sprintf(message, "%d %s", seq_num, temp);
					seq_num++;
					if (SSL_write(ssl, message, strlen(message))) {
						fprintf(stderr, "sendto failed\n");
						break;
					}
				}

				sprintf(message, "%d %s", seq_num, "_END_");
				if (SSL_write(ssl, message, strlen(message))) {
					fprintf(stderr, "sendto failed\n");
					break;
				}
			}


		}

	}

	SSL_CTX_free(ssl_context);
	closesocket(server_socket);

	WSACleanup();

	return 0;
}

int handleRecievedCommand(char* message, int message_length, int* seq_num, int* operation, FILE* client_file) {
	int received_seq_num;
	sscanf(message, "%d", &received_seq_num);


	if (received_seq_num == *seq_num) {
		(*seq_num)++;
	}
	else {
		printf("Received message out of order. Expected sequence number: %d, received: %d\n", *seq_num, received_seq_num);
		return -1;
	}
	message[message_length] = '\0';
	char* space_ptr = strchr(message, ' ');
	if (space_ptr) {
		memmove(message, space_ptr + 1, strlen(space_ptr));
	}
	if (strcmp(message, "disconnect") == 0) {
		return -1;
	}
	else if ((*operation) == 1) {
		if (strcmp(message, "_END_") == 0) {
			return -1;
		}
		fprintf(client_file, "%s\n", message);
		return 0;
	}
	else if (strcmp(message, "save") == 0) {
		(*operation) = 1;
		return 2;
	}
	else if (strcmp(message, "download") == 0) {
		(*operation) = 2;
		return 1;
	}
	else {

		printf("Recieved: %s\n", message);
	}
	return 0;

}

