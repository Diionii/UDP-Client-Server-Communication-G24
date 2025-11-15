#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUFFER_SIZE 65507
#define CHUNK_SIZE  64500  // pak më pak se BUFFER_SIZE për siguri

/* Funksion për komanda të thjeshta që kthejnë tekst */
void send_command(SOCKET sock, struct sockaddr_in *server, const char *cmd)
{
    char buffer[BUFFER_SIZE];
    int server_len = sizeof(*server);

    if (sendto(sock, cmd, (int)strlen(cmd), 0, (struct sockaddr *)server, server_len) == SOCKET_ERROR) {
        printf("Send failed: %d\n", WSAGetLastError());
        return;
    }

    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)server, &server_len);
    if (recv_len == SOCKET_ERROR) {
        printf("No response (timeout or error)\n");
        return;
    }
    buffer[recv_len] = '\0';
    printf("%s\n", buffer);
}

/* ===================== UPLOAD ===================== */
void handle_upload(SOCKET sock, struct sockaddr_in *server, const char *local_path)
{
    FILE *f = fopen(local_path, "rb");
    if (!f) {
        printf("Nuk mund të hapet file-i lokal: %s\n", local_path);
        return;
    }

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (filesize <= 0 || filesize > 10 * 1024 * 1024) {
        printf("File bosh ose shumë i madh (>10 MB)\n");
        fclose(f);
        return;
    }

    const char *filename = strrchr(local_path, '\\');
    if (!filename) filename = strrchr(local_path, '/');
    if (!filename) filename = local_path;
    else filename++;

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/upload %s %ld", filename, filesize);

    int server_len = sizeof(*server);

    /* 1. Dërgo komandën me emër dhe madhësi */
    if (sendto(sock, cmd, (int)strlen(cmd), 0, (struct sockaddr *)server, server_len) == SOCKET_ERROR) {
        printf("Dërgim dështoi: %d\n", WSAGetLastError());
        fclose(f);
        return;
    }

    /* 2. Prit "READY" */
    char resp[64];
    int recv_len = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)server, &server_len);
    if (recv_len <= 0 || strncmp(resp, "READY", 5) != 0) {
        resp[recv_len > 0 ? recv_len : 0] = '\0';
        printf("Serveri nuk është gati: %s\n", recv_len > 0 ? resp : "timeout");
        fclose(f);
        return;
    }

    /* 3. Dërgo të dhënat në copa */
    char chunk[CHUNK_SIZE];
    size_t total_sent = 0;
    while (total_sent < (size_t)filesize) {
        size_t to_read = sizeof(chunk);
        if (total_sent + to_read > (size_t)filesize)
            to_read = (size_t)filesize - total_sent;

        size_t read = fread(chunk, 1, to_read, f);
        if (read == 0) break;

        if (sendto(sock, chunk, (int)read, 0, (struct sockaddr *)server, server_len) == SOCKET_ERROR) {
            printf("Dërgim i copës dështoi\n");
            break;
        }
        total_sent += read;
    }
    fclose(f);

    /* 4. Prit përgjigjen finale */
    recv_len = recvfrom(sock, resp, sizeof(resp) - 1, 0, (struct sockaddr *)server, &server_len);
    if (recv_len > 0) {
        resp[recv_len] = '\0';
        printf("%s\n", resp);
    } else {
        printf("Nuk erdhi përgjigje finale\n");
    }
}

/* ===================== DOWNLOAD ===================== */
void handle_download(SOCKET sock, struct sockaddr_in *server, const char *server_file, const char *local_path)
{
    if (!local_path || local_path[0] == '\0') local_path = server_file;

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/download %s", server_file);

    int server_len = sizeof(*server);

    if (sendto(sock, cmd, (int)strlen(cmd), 0, (struct sockaddr *)server, server_len) == SOCKET_ERROR) {
        printf("Dërgim dështoi\n");
        return;
    }

    char buffer[BUFFER_SIZE];
    int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)server, &server_len);

    if (recv_len == SOCKET_ERROR) {
        printf("Nuk erdhi përgjigje\n");
        return;
    }

    if (recv_len >= 6 && strncmp(buffer, "ERROR:", 6) == 0) {
        buffer[recv_len] = '\0';
        printf("%s\n", buffer);
        return;
    }

    FILE *f = fopen(local_path, "wb");
    if (!f) {
        printf("Nuk mund të krijohet file-i: %s\n", local_path);
        return;
    }

    fwrite(buffer, 1, recv_len, f);
    fclose(f);
    printf("File-i u shkarkua (%d bytes) → %s\n", recv_len, local_path);
}

int main(int argc, char *argv[])
{
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

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(server_ip);

    // Timeout më i madh për upload/download
    int timeout = 30000;  // 15 sekonda
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    printf("Lidhur me serverin %s:%d\n", server_ip, port);

    // Kërko emër dhe rol
    char username[64];
    char role[16];
    printf("Shkruaj emrin e përdoruesit: ");
    scanf("%63s", username);
    printf("Roli (admin/user): ");
    scanf("%15s", role);
    getchar();

    int is_admin = (strcmp(role, "admin") == 0);

    printf("\nPërdoruesi: %s (%s)\n", username, is_admin ? "ADMIN" : "USER");
    printf("Komandat e lejuara:\n");
    if (is_admin) {
        printf("  /list, /read <file>, /upload <lokal>, /download <server> [lokal], /delete <file>, /search <dir> <keyword>\n");
    } else {
        printf("  /list, /read <file>\n");
    }
    printf("  /exit për të dalë\n\n");

    // Login
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
        cmd[strcspn(cmd, "\r\n")] = '\0';  // hiq \n dhe \r

        if (strcmp(cmd, "/exit") == 0) {
            send_command(sock, &server, "/exit");
            printf("Duke dalë...\n");
            break;
        }

        /* ========== UPLOAD ========== */
        if (strncmp(cmd, "/upload ", 8) == 0) {
            if (!is_admin) {
                printf("Nuk ke privilegje admin për upload.\n");
                continue;
            }
            char local_path[512];
            sscanf(cmd + 8, "%511s", local_path);
            if (strlen(local_path) == 0) {
                printf("Përdorimi: /upload <emri_i_file-it_lokal>\n");
            } else {
                handle_upload(sock, &server, local_path);
            }
            continue;
        }

        /* ========== DOWNLOAD ========== */
        if (strncmp(cmd, "/download ", 10) == 0) {
            if (!is_admin) {
                printf("Nuk ke privilegje admin për download.\n");
                continue;
            }
            char server_file[512], local_path[512] = {0};
            char *space = strchr(cmd + 10, ' ');
            if (space) {
                *space = '\0';
                strncpy(local_path, space + 1, sizeof(local_path) - 1);
                local_path[sizeof(local_path) - 1] = '\0';
            }
            strcpy(server_file, cmd + 10);

            if (strlen(server_file) == 0) {
                printf("Përdorimi: /download <emri_në_server> [emri_lokal]\n");
            } else {
                handle_download(sock, &server, server_file, local_path[0] ? local_path : NULL);
            }
            continue;
        }

        /* Kontroll për komanda admin pa privilegje */
        if (!is_admin) {
            if (strncmp(cmd, "/delete", 7) == 0 || strncmp(cmd, "/search", 7) == 0) {
                printf("Nuk ke privilegje për këtë komandë.\n");
                continue;
            }
        }

        /* Të gjitha komandat e tjera (list, read, delete, search, etc.) */
        send_command(sock, &server, cmd);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}