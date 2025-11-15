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
#define INACTIVITY_TIMEOUT 300             // 5 minuta inaktivitet → hiq klientin

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

// ------------------- LOG DHE NDIHMËS -------------------
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

void log_all_stats()
{
    EnterCriticalSection(&stats_lock);
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    FILE *f = fopen("server_stats.txt", "a");
    if (f)
    {
        fprintf(f, "[%s] === SERVER STATS ===\n", ts);
        fprintf(f, "Active clients   : %d / %d\n", client_count, MAX_CLIENTS);
        fprintf(f, "Total RX         : %ld bytes\n", total_bytes_received);
        fprintf(f, "Total TX         : %ld bytes\n\n", total_bytes_sent);
        fprintf(f, "Active clients details:\n");

        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].active)
            {
                long idle = now - clients[i].last_activity;
                fprintf(f, "  • %s:%u | %s%s | msgs:%d | RX:%ld | TX:%ld | idle:%ld s\n",
                    clients[i].ip, clients[i].port, clients[i].name,
                    clients[i].is_admin ? " [ADMIN]" : "",
                    clients[i].msg_count, clients[i].bytes_received,
                    clients[i].bytes_sent, idle);
            }
        }
        fprintf(f, "--------------------------------------------------\n\n");
        fclose(f);
    }
    LeaveCriticalSection(&stats_lock);
}

// ------------------- KLIENTËT -------------------
int sockaddr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

Client *find_client(const struct sockaddr_in *addr)
{
    EnterCriticalSection(&stats_lock);
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i].active && sockaddr_equal(&clients[i].addr, addr))
        {
            LeaveCriticalSection(&stats_lock);
            return &clients[i];
        }
    }
    LeaveCriticalSection(&stats_lock);
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

// ------------------- CLEANUP THREAD (INACTIVITY) -------------------
DWORD WINAPI cleanup_thread(LPVOID param)
{
    while (1)
    {
        Sleep(60000); // çdo minutë
        time_t now = time(NULL);

        EnterCriticalSection(&stats_lock);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].active && (now - clients[i].last_activity > INACTIVITY_TIMEOUT))
            {
                log_message("INACTIVITY TIMEOUT → removing %s:%u (%s)", clients[i].ip, clients[i].port, clients[i].name);
                clients[i].active = 0;
                client_count--;
            }
        }
        LeaveCriticalSection(&stats_lock);

        log_all_stats(); // regjistrim periodik i statistikave
    }
    return 0;
}

// ------------------- FUNKSIONET E KOMANDAVE (me Client *c për statistika) -------------------
void safe_send(SOCKET s, const char *data, int len, const struct sockaddr_in *addr, Client *c)
{
    if (len <= 0) len = (int)strlen(data);
    int sent = sendto(s, data, len, 0, (struct sockaddr *)addr, sizeof(*addr));
    if (sent > 0)
    {
        EnterCriticalSection(&stats_lock);
        total_bytes_sent += sent;
        if (c) c->bytes_sent += sent;
        LeaveCriticalSection(&stats_lock);
    }
}

int handle_list(SOCKET s, const char *path, const struct sockaddr_in *addr, Client *c)
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
        safe_send(s, out, -1, addr, c);
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
    safe_send(s, out, (int)outlen, addr, c);
    return 0;
}

int handle_read(SOCKET s, const char *file, const struct sockaddr_in *addr, Client *c)
{
    FILE *f = fopen(file, "rb");
    if (!f)
    {
        char out[256];
        snprintf(out, sizeof(out), "ERROR: Cannot open %s", file);
        safe_send(s, out, -1, addr, c);
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
        safe_send(s, out, -1, addr, c);
        return 0;
    }

    char *buf = (char *)malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);
    safe_send(s, buf, (int)sz, addr, c);
    free(buf);
    return 0;
}

int handle_delete(const char *file, const struct sockaddr_in *addr, SOCKET s, Client *c)
{
    if (DeleteFileA(file))
    {
        char out[256];
        snprintf(out, sizeof(out), "File %s deleted", file);
        safe_send(s, out, -1, addr, c);
    }
    else
    {
        char out[256];
        snprintf(out, sizeof(out), "ERROR: Cannot delete %s", file);
        safe_send(s, out, -1, addr, c);
    }
    return 0;
}

int handle_search(const char *keyword, const char *dir, SOCKET s, const struct sockaddr_in *addr, Client *c)
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
        safe_send(s, out, -1, addr, c);
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

    safe_send(s, out, (int)outlen, addr, c);
    return 0;
}

// ------------------- CONSOLE THREAD (STATS, EXIT) -------------------
DWORD WINAPI stdin_thread(LPVOID param)
{
    char buf[256];
    while (1)
    {
        if (!fgets(buf, sizeof(buf), stdin)) break;
        buf[strcspn(buf, "\r\n")] = 0;

        if (_stricmp(buf, "STATS") == 0)
        {
            EnterCriticalSection(&stats_lock);
            time_t now = time(NULL);
            printf("\n=== SERVER STATS ===\n");
            printf("Active clients : %d / %d\n", client_count, MAX_CLIENTS);
            printf("Total RX       : %ld bytes\n", total_bytes_received);
            printf("Total TX       : %ld bytes\n\n", total_bytes_sent);

            for (int i = 0; i < MAX_CLIENTS; i++)
            {
                if (clients[i].active)
                {
                    long idle = now - clients[i].last_activity;
                    printf(" • %s:%u | %-15s%s | msgs:%-4d | RX:%-10ld | TX:%-10ld | idle:%-4ld s\n",
                        clients[i].ip, clients[i].port, clients[i].name,
                        clients[i].is_admin ? " [ADMIN]" : "",
                        clients[i].msg_count, clients[i].bytes_received,
                        clients[i].bytes_sent, idle);
                }
            }
            printf("==============================\n\n");
            LeaveCriticalSection(&stats_lock);
        }
        else if (_stricmp(buf, "EXIT") == 0 || _stricmp(buf, "QUIT") == 0)
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

// ------------------- MAIN -------------------
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
    CreateThread(NULL, 0, cleanup_thread, NULL, 0, NULL);

    printf("UDP Admin Server running on %s:%u\n", SERVER_IP, SERVER_PORT);
    printf("Type 'STATS' for live stats, 'EXIT' to stop\n");

    while (1)
    {
        int recv_len = recvfrom(s, buf, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &slen);
        if (recv_len == SOCKET_ERROR) continue;

        buf[recv_len] = '\0';

        Client *c = find_client(&client_addr);

        // Log çdo mesazh të pranuar (për monitorim)
        if (c)
            log_message("FROM %s:%u (%s): %s", c->ip, c->port, c->name, buf);
        else
            log_message("FROM %s:%u (unknown): %s", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buf);

        char cmd[16] = {0}, arg1[512] = {0};
        sscanf(buf, "%15s %511[^\n]", cmd, arg1);

        char reply[BUFFER_SIZE] = "ERROR: Unknown command";

        // --- HELLO / LOGIN ---
        if (strcmp(cmd, "HELLO") == 0 || strcmp(cmd, "/login") == 0)
        {
            if (!c)
            {
                int is_admin = (strstr(buf, ADMIN_TOKEN) != NULL) ? 1 : 0;
                char name[NAME_LEN];
                strncpy(name, arg1, NAME_LEN - 1);
                name[NAME_LEN - 1] = '\0';
                c = add_client(&client_addr, name[0] ? name : NULL, is_admin);
                if (c)
                    snprintf(reply, sizeof(reply), "WELCOME %s%s", c->name, is_admin ? " [ADMIN]" : "");
                else
                    snprintf(reply, sizeof(reply), "ERROR: Server full (max %d clients)", MAX_CLIENTS);
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
                handle_list(s, arg1[0] ? arg1 : ".", &client_addr, c);
                continue;
            }
            else if (strcmp(cmd, "/read") == 0 || strcmp(cmd, "/download") == 0)
            {
                handle_read(s, arg1, &client_addr, c);
                continue;
            }
            else if (strcmp(cmd, "/delete") == 0)
            {
                handle_delete(arg1, &client_addr, s, c);
                continue;
            }
            else if (strcmp(cmd, "/search") == 0)
            {
                char *space = strchr(arg1, ' ');
                if (space)
                {
                    *space = '\0';
                    handle_search(space + 1, arg1, s, &client_addr, c);
                }
                else
                    snprintf(reply, sizeof(reply), "ERROR: Usage /search <dir> <keyword>");
                continue;
            }
            else if (strcmp(cmd, "/info") == 0)
{
    char filename[256];
    if (sscanf(arg1, "%255s", filename) != 1 || !filename[0])
    {
        snprintf(reply, sizeof(reply), "ERROR: Usage /info <filename>");
    }
    else if (strstr(filename, "..") || strchr(filename, '/') || strchr(filename, '\\'))
    {
        snprintf(reply, sizeof(reply), "ERROR: Invalid filename");
    }
    else
    {
        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", UPLOAD_DIR, filename);

        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(fullpath, &fd);
        if (h == INVALID_HANDLE_VALUE)
        {
            snprintf(reply, sizeof(reply), "ERROR: File not found");
        }
        else
        {
            FindClose(h);

            FILETIME ftCreate = fd.ftCreationTime;
            FILETIME ftModify = fd.ftLastWriteTime;
            SYSTEMTIME stCreate, stModify;
            FileTimeToSystemTime(&ftCreate, &stCreate);
            FileTimeToSystemTime(&ftModify, &stModify);

            char create_str[64], modify_str[64];
            snprintf(create_str, sizeof(create_str), "%04d-%02d-%02d %02d:%02d:%02d",
                     stCreate.wYear, stCreate.wMonth, stCreate.wDay,
                     stCreate.wHour, stCreate.wMinute, stCreate.wSecond);
            snprintf(modify_str, sizeof(modify_str), "%04d-%02d-%02d %02d:%02d:%02d",
                     stModify.wYear, stModify.wMonth, stModify.wDay,
                     stModify.wHour, stModify.wMinute, stModify.wSecond);

            snprintf(reply, sizeof(reply),
                     "INFO %s\n"
                     "Size: %lu bytes\n"
                     "Created: %s\n"
                     "Modified: %s",
                     filename, fd.nFileSizeLow, create_str, modify_str);
        }
    }
    safe_send(s, reply, -1, &client_addr, c);
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
                        safe_send(s, "READY", 5, &client_addr, c);

                        long received = 0;
                        struct timeval tv = {10, 0};
                        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

                        while (received < filesize)
                        {
                            int n = recvfrom(s, buf, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &slen);
                            if (n <= 0) break;
                            size_t write_sz = (received + n > filesize) ? (filesize - received) : n;
                            fwrite(buf, 1, write_sz, f);

                            EnterCriticalSection(&stats_lock);
                            received += write_sz;
                            total_bytes_received += write_sz;
                            c->bytes_received += write_sz;
                            LeaveCriticalSection(&stats_lock);
                        }

                        fclose(f);
                        tv.tv_sec = 0;
                        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

                        if (received == filesize)
                            snprintf(reply, sizeof(reply), "UPLOADED %s (%ld bytes)", filename, filesize);
                        else
                            snprintf(reply, sizeof(reply), "ERROR: Incomplete upload (%ld/%ld bytes)", received, filesize);
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
            snprintf(reply, sizeof(reply), "ERROR: Use HELLO or /login first");
        }

        // Dërgo përgjigje (përveç rasteve me continue)
        if (reply[0])
            safe_send(s, reply, -1, &client_addr, c);

        // Update statistikat e klientit
        if (c)
        {
            EnterCriticalSection(&stats_lock);
            c->last_activity = time(NULL);
            c->msg_count++;
            c->bytes_received += recv_len;
            total_bytes_received += recv_len;
            LeaveCriticalSection(&stats_lock);
        }
    }

    closesocket(s);
    WSACleanup();
    DeleteCriticalSection(&stats_lock);
    return 0;
}