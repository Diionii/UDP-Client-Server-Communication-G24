#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_PORT 7777
#define BUFFER_SIZE 65507
#define MAX_CLIENTS 100
#define TIMEOUT_SECONDS 30

typedef struct {
    struct sockaddr_in addr;
    int active;
    unsigned long last_activity;
    unsigned long messages_received;
    unsigned long bytes_received;
} Client;

Client clients[MAX_CLIENTS];

FILE* logfile;

unsigned long total_bytes_received = 0;
unsigned long total_messages = 0;

void log_message(const char* msg) {
    logfile = fopen("server_log.txt", "a");
    if (logfile) {
        fprintf(logfile, "[%ld] %s\n", time(NULL), msg);
        fclose(logfile);
    }
}

int find_client(struct sockaddr_in* addr) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active &&
            clients[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            clients[i].addr.sin_port == addr->sin_port) {
            return i;
        }
    }
    return -1;
}

int add_client(struct sockaddr_in* addr) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].active = 1;
            clients[i].addr = *addr;
            clients[i].last_activity = time(NULL);
            clients[i].messages_received = 0;
            clients[i].bytes_received = 0;

            char msg[128];
            sprintf(msg, "New client connected: %s : %d",
                inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
            log_message(msg);

            return i;
        }
    }
    return -1;
}

void remove_inactive_clients() {
    unsigned long now = time(NULL);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active &&
            now - clients[i].last_activity > TIMEOUT_SECONDS) {

            char buffer[256];
            sprintf(buffer,
                "Client timed out: %s : %d",
                inet_ntoa(clients[i].addr.sin_addr),
                ntohs(clients[i].addr.sin_port));
            log_message(buffer);

            clients[i].active = 0;
        }
    }
}

DWORD WINAPI console_thread(LPVOID lpParam) {
    char command[32];

    while (1) {
        printf("\n> ");
        scanf("%s", command);

        if (strcmp(command, "STATS") == 0) {
            printf("\n=== Server Statistics ===\n");
            printf("Total bytes received: %lu\n", total_bytes_received);
            printf("Total messages: %lu\n\n", total_messages);

            printf("Active Clients:\n");
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active) {
                    printf("%s : %d | messages: %lu | bytes: %lu\n",
                        inet_ntoa(clients[i].addr.sin_addr),
                        ntohs(clients[i].addr.sin_port),
                        clients[i].messages_received,
                        clients[i].bytes_received);
                }
            }
        }
    }

    return 0;
}

int main() {
    WSADATA wsa;
    SOCKET serverSocket;
    struct sockaddr_in serverAddr, clientAddr;

    int clientLen = sizeof(clientAddr);
    char buffer[BUFFER_SIZE];

    WSAStartup(MAKEWORD(2, 2), &wsa);

    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    CreateThread(NULL, 0, console_thread, NULL, 0, NULL);

    printf("UDP Server running on port %d...\n", SERVER_PORT);

    while (1) {
        int bytes = recvfrom(
            serverSocket,
            buffer,
            BUFFER_SIZE,
            0,
            (struct sockaddr*)&clientAddr,
            &clientLen
        );

        buffer[bytes] = '\0';

        int id = find_client(&clientAddr);
        if (id < 0) id = add_client(&clientAddr);

        if (id >= 0) {
            clients[id].messages_received++;
            clients[id].bytes_received += bytes;
            clients[id].last_activity = time(NULL);

            total_messages++;
            total_bytes_received += bytes;

            printf("(%s:%d) -> %s\n",
                inet_ntoa(clientAddr.sin_addr),
                ntohs(clientAddr.sin_port),
                buffer);
        }

        remove_inactive_clients();
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
