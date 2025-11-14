#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUFFER_SIZE 65507

void send_command(SOCKET sock, struct sockaddr_in *server, const char *cmd) {
    char buffer[BUFFER_SIZE];
    int server_len = sizeof(*server);
    int recv_len;

    // Dërgo komandën
    if (sendto(sock, cmd, (int)strlen(cmd), 0, (struct sockaddr *)server, server_len) == SOCKET_ERROR) {
        printf("Send failed: %d\n", WSAGetLastError());
        return;
    }

    // Prit përgjigje
    recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)server, &server_len);
    if (recv_len == SOCKET_ERROR) {
        printf("No response (timeout or error)\n");
        return;
    }
    buffer[recv_len] = '\0';
    printf("Server response:\n%s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);

    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char cmd[1024];

    // Inicializim Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Krijo socket UDP
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(server_ip);

    // Vendos timeout për përgjigje
    int timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    printf("Lidhur me serverin %s:%d\n", server_ip, port);

    // Kërko emër përdoruesi dhe privilegje
    char username[64];
    char role[16];
    printf("Shkruaj emrin e përdoruesit: ");
    scanf("%63s", username);
    printf("Roli (admin/user): ");
    scanf("%15s", role);
    getchar(); // pastrimi i newline

    int is_admin = (strcmp(role, "admin") == 0);

    printf("\nPërdoruesi: %s (%s)\n", username, is_admin ? "ADMIN" : "USER");
    printf("Komandat e lejuara:\n");
    if (is_admin) {
        printf("  /list, /read <file>, /upload <file>, /download <file>, /delete <file>, /search <keyword>\n");
    } else {
        printf("  /list, /read <file>\n");
    }
    printf("  /exit për të dalë\n\n");

    /* Send HELLO/LOGIN command with username and token to register as admin */
    char login_cmd[256];
    if (is_admin) {
        snprintf(login_cmd, sizeof(login_cmd), "/login %s secret_admin_token", username);
    } else {
        snprintf(login_cmd, sizeof(login_cmd), "/login %s", username);
    }
    printf("[DEBUG] Sending login: '%s'\n", login_cmd);
    send_command(sock, &server, login_cmd);
    printf("[DEBUG] Login response received\n");

    while (1) {
        printf(">> ");
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        if (cmd[strlen(cmd) - 1] == '\n') cmd[strlen(cmd) - 1] = '\0';

        if (strcmp(cmd, "/exit") == 0) {
            printf("Duke dalë...\n");
            break;
        }

        if (!is_admin) {
            if (strncmp(cmd, "/upload", 7) == 0 || strncmp(cmd, "/delete", 7) == 0 ||
                strncmp(cmd, "/download", 9) == 0 || strncmp(cmd, "/search", 7) == 0) {
                printf("❌ Nuk ke privilegje për këtë komandë.\n");
                continue;
            }
        }

        send_command(sock, &server, cmd);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}