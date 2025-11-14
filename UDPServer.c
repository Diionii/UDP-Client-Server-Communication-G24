#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#pragma comment(lib, "Ws2_32.lib")

#define MAX_CLIENTS 100
#define BUFFER_SIZE 65507
#define NAME_LEN 64
#define ADMIN_TOKEN "secret_admin_token"
#define DEFAULT_PORT 9000
#define DEFAULT_BIND_IP "0.0.0.0"
#define MAX_UPLOAD_SIZE (10 * 1024 * 1024)  // 10MB
#define UPLOAD_DIR "uploads"

typedef struct
{
    struct sockaddr_in addr;
    char ip[INET_ADDRSTRLEN];
    unsigned short port;
    char name[NAME_LEN];
    time_t last_activity;
    int msg_count;
    long bytes_received;
    long bytes_sent;
    int active;
    int is_admin;
} Client;

static Client clients[MAX_CLIENTS];
static int client_count = 0;
static unsigned short SERVER_PORT = DEFAULT_PORT;
static char SERVER_IP[64] = DEFAULT_BIND_IP;
static long total_bytes_received = 0;
static long total_bytes_sent = 0;
static CRITICAL_SECTION stats_lock;
FILE *log_fp = NULL;

void log_message(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (!log_fp)
        log_fp = fopen("server_log.txt", "a");
    time_t t = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    if (log_fp)
    {
        fprintf(log_fp, "[%s] ", ts);
        vfprintf(log_fp, fmt, ap);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    va_end(ap);
}

int sockaddr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

Client *find_client(const struct sockaddr_in *addr)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i].active && sockaddr_equal(&clients[i].addr, addr))
            return &clients[i];
    }
    return NULL;
}

Client *add_client(const struct sockaddr_in *addr, const char *name, int is_admin)
{
    EnterCriticalSection(&stats_lock);
    if (client_count >= MAX_CLIENTS)
    {
        LeaveCriticalSection(&stats_lock);
        return NULL;
    }
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (!clients[i].active)
        {
            clients[i].addr = *addr;
            strcpy(clients[i].ip, inet_ntoa(addr->sin_addr));
            clients[i].port = ntohs(addr->sin_port);
            if (name && name[0])
                strncpy(clients[i].name, name, NAME_LEN - 1);
            else
                strcpy(clients[i].name, "guest");
            clients[i].name[NAME_LEN - 1] = '\0';
            clients[i].last_activity = time(NULL);
            clients[i].msg_count = 0;
            clients[i].bytes_received = 0;
            clients[i].bytes_sent = 0;
            clients[i].active = 1;
            clients[i].is_admin = is_admin;
            client_count++;
            LeaveCriticalSection(&stats_lock);
            log_message("Client added %s:%u (%s)%s", clients[i].ip, clients[i].port, clients[i].name, is_admin ? " [ADMIN]" : "");
            return &clients[i];
        }
    }
    LeaveCriticalSection(&stats_lock);
    return NULL;
}

void remove_client(Client *c)
{
    if (!c) return;
    EnterCriticalSection(&stats_lock);
    if (c->active)
    {
        log_message("Client removed %s:%u (%s)", c->ip, c->port, c->name);
        c->active = 0;
        client_count--;
    }
    LeaveCriticalSection(&stats_lock);
}

// --- FUNKSIONET E KOMANDAVE ---

int handle_list(SOCKET s, const char *path, const struct sockaddr_in *addr)
{
    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", path);
    HANDLE h = FindFirstFileA(search, &fd);
    char out[BUFFER_SIZE];
    size_t outlen = 0;

    if (h == INVALID_HANDLE_VALUE)
    {
        snprintf(out, sizeof(out), "ERROR: Cannot list %s", path);
        sendto(s, out, (int)strlen(out), 0, (struct sockaddr *)addr, sizeof(*addr));
        total_bytes_sent += strlen(out);
        return 0;
    }

    do
    {
        const char *prefix = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "[DIR] " : "[FILE] ";
        int n = snprintf(out + outlen, sizeof(out) - outlen, "%s%s\n", prefix, fd.cFileName);
        if (n < 0 || outlen + n >= sizeof(out) - 200) break;
        outlen += n;
    } while (FindNextFileA(h, &fd));

    FindClose(h);
    sendto(s, out, (int)outlen, 0, (struct sockaddr *)addr, sizeof(*addr));
    total_bytes_sent += outlen;
    return 0;
}

int handle_read(SOCKET s, const char *file, const struct sockaddr_in *addr)
{
    FILE *f = fopen(file, "rb");
    if (!f)
    {
        char out[256];
        snprintf(out, sizeof(out), "ERROR: Cannot open %s", file);
        sendto(s, out, (int)strlen(out), 0, (struct sockaddr *)addr, sizeof(*addr));
        total_bytes_sent += strlen(out);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz > BUFFER_SIZE - 128)
    {
        fclose(f);
        char out[256];
        snprintf(out, sizeof(out), "ERROR: File too big (>64KB)");
        sendto(s, out, (int)strlen(out), 0, (struct sockaddr *)addr, sizeof(*addr));
        total_bytes_sent += strlen(out);
        return 0;
    }

    char *buf = (char *)malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);
    sendto(s, buf, (int)sz, 0, (struct sockaddr *)addr, sizeof(*addr));
    total_bytes_sent += sz;
    free(buf);
    return 0;
}

int handle_delete(const char *file, const struct sockaddr_in *addr, SOCKET s)
{
    if (DeleteFileA(file))
    {
        char out[256];
        snprintf(out, sizeof(out), "File %s deleted", file);
        sendto(s, out, (int)strlen(out), 0, (struct sockaddr *)addr, sizeof(*addr));
        total_bytes_sent += strlen(out);
    }
    else
    {
        char out[256];
        snprintf(out, sizeof(out), "ERROR: Cannot delete %s", file);
        sendto(s, out, (int)strlen(out), 0, (struct sockaddr *)addr, sizeof(*addr));
        total_bytes_sent += strlen(out);
    }
    return 0;
}

int handle_search(const char *keyword, const char *dir, SOCKET s, const struct sockaddr_in *addr)
{
    WIN32_FIND_DATAA fd;
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\*", dir);
    HANDLE h = FindFirstFileA(path, &fd);
    char out[BUFFER_SIZE];
    size_t outlen = 0;

    if (h == INVALID_HANDLE_VALUE)
    {
        snprintf(out, sizeof(out), "ERROR: Cannot access %s", dir);
        sendto(s, out, (int)strlen(out), 0, (struct sockaddr *)addr, sizeof(*addr));
        total_bytes_sent += strlen(out);
        return 0;
    }

    int found = 0;
    do
    {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            char filepath[MAX_PATH];
            snprintf(filepath, sizeof(filepath), "%s\\%s", dir, fd.cFileName);
            FILE *f = fopen(filepath, "r");
            if (f)
            {
                char line[1024];
                int line_num = 0;
                while (fgets(line, sizeof(line), f))
                {
                    line_num++;
                    if (strstr(line, keyword))
                    {
                        int n = snprintf(out + outlen, sizeof(out) - outlen, "%s:%d: %s", fd.cFileName, line_num, line);
                        if (n < 0 || outlen + n >= sizeof(out) - 200) { fclose(f); break; }
                        outlen += n;
                        found = 1;
                    }
                }
                fclose(f);
            }
        }
    } while (FindNextFileA(h, &fd) && outlen < sizeof(out) - 200);

    FindClose(h);

    if (!found)
    {
        snprintf(out, sizeof(out), "No matches for '%s'", keyword);
        outlen = strlen(out);
    }

    sendto(s, out, (int)outlen, 0, (struct sockaddr *)addr, sizeof(*addr));
    total_bytes_sent += outlen;
    return 0;
}

// --- THREAD PËR KOMANDAT NGA CONSOLE ---
DWORD WINAPI stdin_thread(LPVOID param)
{
    char buf[256];
    while (1)
    {
        if (!fgets(buf, sizeof(buf), stdin)) break;
        buf[strcspn(buf, "\r\n")] = 0;  // hiq \n

        if (strcmp(buf, "STATS") == 0)
        {
            EnterCriticalSection(&stats_lock);
            printf("Active clients: %d\n", client_count);
            printf("Total RX: %ld bytes | TX: %ld bytes\n", total_bytes_received, total_bytes_sent);
            LeaveCriticalSection(&stats_lock);
        }
        else if (strcmp(buf, "EXIT") == 0 || strcmp(buf, "QUIT") == 0)
        {
            exit(0);
        }
        else
        {
            printf("Commands: STATS, EXIT\n");
        }
    }
    return 0;
}

// --- MAIN ---
int main(int argc, char **argv)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server_addr, client_addr;
    int slen = sizeof(client_addr);
    char buf[BUFFER_SIZE + 1];

    if (argc >= 2) SERVER_PORT = (unsigned short)atoi(argv[1]);
    if (argc >= 3) strncpy(SERVER_IP, argv[2], sizeof(SERVER_IP) - 1);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("WSAStartup failed\n");
        return 1;
    }

    InitializeCriticalSection(&stats_lock);

    // Krijo dosjen uploads
    CreateDirectoryA(UPLOAD_DIR, NULL);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
    {
        printf("Socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    ZeroMemory(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (bind(s, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 1;
    }

    CreateThread(NULL, 0, stdin_thread, NULL, 0, NULL);
    printf("UDP Admin Server running on %s:%u\n", SERVER_IP, SERVER_PORT);
    printf("Type 'STATS' or 'EXIT'\n");

    while (1)
    {
        int recv_len = recvfrom(s, buf, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &slen);
        if (recv_len == SOCKET_ERROR) continue;

        buf[recv_len] = '\0';
        Client *c = find_client(&client_addr);
        char cmd[16] = {0}, arg1[512] = {0};
        sscanf(buf, "%15s %511[^\n]", cmd, arg1);

        char reply[BUFFER_SIZE];
        reply[0] = '\0';

        // --- HELLO / LOGIN ---
        if (strcmp(cmd, "HELLO") == 0 || strcmp(cmd, "/login") == 0)
        {
            if (!c)
            {
                int is_admin = strstr(buf, ADMIN_TOKEN) ? 1 : 0;
                char name[NAME_LEN];
                strncpy(name, arg1, NAME_LEN - 1);
                name[NAME_LEN - 1] = '\0';
                c = add_client(&client_addr, name[0] ? name : "guest", is_admin);
                if (c)
                    snprintf(reply, sizeof(reply), "WELCOME %s%s", c->name, is_admin ? " [ADMIN]" : "");
                else
                    snprintf(reply, sizeof(reply), "ERROR: Server full");
            }
            else
            {
                snprintf(reply, sizeof(reply), "WELCOME back %s", c->name);
            }
        }

        // --- KOMANDAT ADMIN ---
        else if (c && c->is_admin)
        {
            if (strcmp(cmd, "/list") == 0)
            {
                handle_list(s, arg1[0] ? arg1 : ".", &client_addr);
                continue;
            }
            else if (strcmp(cmd, "/read") == 0 || strcmp(cmd, "/download") == 0)
            {
                handle_read(s, arg1, &client_addr);
                continue;
            }
            else if (strcmp(cmd, "/delete") == 0)
            {
                handle_delete(arg1, &client_addr, s);
                continue;
            }
            else if (strcmp(cmd, "/search") == 0)
            {
                char *space = strchr(arg1, ' ');
                if (space) { *space = '\0'; handle_search(space + 1, arg1, s, &client_addr); }
                else snprintf(reply, sizeof(reply), "ERROR: /search <dir> <keyword>");
                continue;
            }
            else if (strcmp(cmd, "/upload") == 0)
            {
                char filename[256];
                long filesize = 0;
                if (sscanf(arg1, "%255s %ld", filename, &filesize) != 2 || filesize <= 0 || filesize > MAX_UPLOAD_SIZE)
                {
                    snprintf(reply, sizeof(reply), "ERROR: /upload <file> <size> (max 10MB)");
                }
                else if (strstr(filename, "..") || strchr(filename, '/') || strchr(filename, '\\'))
                {
                    snprintf(reply, sizeof(reply), "ERROR: Invalid filename");
                }
                else
                {
                    char safe_path[MAX_PATH];
                    snprintf(safe_path, sizeof(safe_path), "%s/%s", UPLOAD_DIR, filename);
                    FILE *f = fopen(safe_path, "wb");
                    if (!f)
                    {
                        snprintf(reply, sizeof(reply), "ERROR: Cannot create file");
                    }
                    else
                    {
                        sendto(s, "READY", 5, 0, (struct sockaddr *)&client_addr, slen);
                        total_bytes_sent += 5;

                        long received = 0;
                        struct timeval tv = {5, 0};
                        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

                        while (received < filesize)
                        {
                            int n = recvfrom(s, buf, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &slen);
                            if (n <= 0) break;
                            size_t write_sz = (received + n > filesize) ? (filesize - received) : n;
                            fwrite(buf, 1, write_sz, f);
                            received += write_sz;
                            total_bytes_received += write_sz;
                        }

                        fclose(f);
                        tv.tv_sec = 0;
                        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

                        if (received == filesize)
                            snprintf(reply, sizeof(reply), "UPLOADED %s (%ld bytes)", filename, filesize);
                        else
                            snprintf(reply, sizeof(reply), "ERROR: Incomplete (%ld/%ld)", received, filesize);
                    }
                }
            }
            else if (strcmp(cmd, "/exit") == 0)
            {
                snprintf(reply, sizeof(reply), "GOODBYE");
                remove_client(c);
            }
            else
            {
                snprintf(reply, sizeof(reply), "ERROR: Unknown command");
            }
        }
        else if (c)
        {
            snprintf(reply, sizeof(reply), "ERROR: Admin access required");
        }
        else
        {
            snprintf(reply, sizeof(reply), "ERROR: Use /login first");
        }

        // --- DËRGO PËRGJIGJE ---
        if (reply[0])
        {
            int sent = sendto(s, reply, (int)strlen(reply), 0, (struct sockaddr *)&client_addr, slen);
            if (sent != SOCKET_ERROR)
                total_bytes_sent += sent;
        }

        // Update stats
        if (c)
        {
            c->last_activity = time(NULL);
            c->msg_count++;
            c->bytes_received += recv_len;
        }
    }

    closesocket(s);
    WSACleanup();
    DeleteCriticalSection(&stats_lock);
    return 0;
}