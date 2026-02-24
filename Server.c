#define _CRT_SECURE_NO_WARNINGS 1
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <stdint.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"user32.lib")

#define SERVER_PORT      9999
#define AUTH_USERNAME    "admin"
#define AUTH_PASSWORD    "123456"
#define ENCRYPT_KEY      "SecureKey2026"
#define KEY_LENGTH       12
#define BUFFER_SIZE      4096
#define LOGIN_BUF_SIZE   64
#define FILE_BUF_SIZE    1024

#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_PURPLE  "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_RESET   "\033[0m"

static void ClearConsole(void);
static void XorEncryptDecrypt(char* data, int data_len, const char* key, int key_len);
static void ReadProcessMemorySafe(DWORD pid, LPVOID address, int* out_value);
static BOOL WriteProcessMemorySafe(DWORD pid, LPVOID address, int value);
static void ExecuteSystemCommand(const char* cmd, char* output, int max_output_len);
static void ListAllProcesses(char* output);
static void SendFileToClient(SOCKET client_socket, const char* file_path);
static void ReceiveFileFromClient(SOCKET client_socket, const char* file_path);
static int AuthenticateClient(SOCKET client_socket);
static void ShowServerLogo(void);
static void HandleClientConnection(SOCKET client_socket);
static int InitializeWinsock(void);
static void CleanupServerResources(SOCKET server_socket);

static void ClearConsole(void) {
    system("cls");
}

static void XorEncryptDecrypt(char* data, int data_len, const char* key, int key_len) {
    if (data == NULL || key == NULL || data_len <= 0 || key_len <= 0) {
        return;
    }
    for (int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

static void ReadProcessMemorySafe(DWORD pid, LPVOID address, int* out_value) {
    if (out_value == NULL) {
        return;
    }
    *out_value = 0;

    HANDLE process_handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (process_handle == NULL) {
        return;
    }

    ReadProcessMemory(process_handle, address, out_value, sizeof(int), NULL);
    CloseHandle(process_handle);
}

static BOOL WriteProcessMemorySafe(DWORD pid, LPVOID address, int value) {
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process_handle == NULL) {
        return FALSE;
    }

    BOOL write_success = WriteProcessMemory(process_handle, address, &value, sizeof(int), NULL);
    CloseHandle(process_handle);
    return write_success;
}

static void ExecuteSystemCommand(const char* cmd, char* output, int max_output_len) {
    if (cmd == NULL || output == NULL || max_output_len <= 0) {
        strncpy(output, "ERROR", max_output_len);
        return;
    }

    FILE* pipe = _popen(cmd, "r");
    if (pipe == NULL) {
        strncpy(output, "ERROR", max_output_len);
        return;
    }

    output[0] = '\0';
    char buffer[256] = { 0 };
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        if (strlen(output) + strlen(buffer) < (unsigned int)max_output_len) {
            strcat(output, buffer);
        }
        else {
            break;
        }
        memset(buffer, 0, sizeof(buffer));
    }

    _pclose(pipe);
}

static void ListAllProcesses(char* output) {
    if (output == NULL) {
        return;
    }
    output[0] = '\0';

    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot_handle == INVALID_HANDLE_VALUE) {
        strcpy(output, "Failed to create process snapshot");
        return;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot_handle, &process_entry)) {
        do {
            char process_info[256] = { 0 };
            snprintf(process_info, sizeof(process_info), "%-6d %s\n",
                process_entry.th32ProcessID, process_entry.szExeFile);

            if (strlen(output) + strlen(process_info) < BUFFER_SIZE) {
                strcat(output, process_info);
            }
        } while (Process32Next(snapshot_handle, &process_entry));
    }

    CloseHandle(snapshot_handle);
}

static void SendFileToClient(SOCKET client_socket, const char* file_path) {
    if (file_path == NULL || strlen(file_path) == 0) {
        send(client_socket, "FAIL", 4, 0);
        return;
    }

    FILE* file_handle = fopen(file_path, "rb");
    if (file_handle == NULL) {
        send(client_socket, "FAIL", 4, 0);
        return;
    }

    send(client_socket, "OK", 2, 0);

    char file_buffer[FILE_BUF_SIZE] = { 0 };
    int bytes_read = 0;
    while ((bytes_read = fread(file_buffer, 1, FILE_BUF_SIZE, file_handle)) > 0) {
        XorEncryptDecrypt(file_buffer, bytes_read, ENCRYPT_KEY, KEY_LENGTH);
        send(client_socket, file_buffer, bytes_read, 0);
        memset(file_buffer, 0, FILE_BUF_SIZE);
    }

    fclose(file_handle);
}

static void ReceiveFileFromClient(SOCKET client_socket, const char* file_path) {
    if (file_path == NULL || strlen(file_path) == 0) {
        return;
    }

    FILE* file_handle = fopen(file_path, "wb");
    if (file_handle == NULL) {
        return;
    }

    char file_buffer[FILE_BUF_SIZE] = { 0 };
    int bytes_received = 0;
    while ((bytes_received = recv(client_socket, file_buffer, FILE_BUF_SIZE, 0)) > 0) {
        XorEncryptDecrypt(file_buffer, bytes_received, ENCRYPT_KEY, KEY_LENGTH);
        fwrite(file_buffer, 1, bytes_received, file_handle);
        memset(file_buffer, 0, FILE_BUF_SIZE);
    }

    fclose(file_handle);
}

static int AuthenticateClient(SOCKET client_socket) {
    char username[LOGIN_BUF_SIZE] = { 0 };
    char password[LOGIN_BUF_SIZE] = { 0 };

    int recv_user = recv(client_socket, username, LOGIN_BUF_SIZE, 0);
    int recv_pass = recv(client_socket, password, LOGIN_BUF_SIZE, 0);

    if (recv_user <= 0 || recv_pass <= 0) {
        send(client_socket, "FAIL", 4, 0);
        return 0;
    }

    XorEncryptDecrypt(username, LOGIN_BUF_SIZE, ENCRYPT_KEY, KEY_LENGTH);
    XorEncryptDecrypt(password, LOGIN_BUF_SIZE, ENCRYPT_KEY, KEY_LENGTH);

    if (strcmp(username, AUTH_USERNAME) == 0 && strcmp(password, AUTH_PASSWORD) == 0) {
        send(client_socket, "OK", 2, 0);
        return 1;
    }

    send(client_socket, "FAIL", 4, 0);
    return 0;
}

static void ShowServerLogo(void) {
    ClearConsole();
    SetConsoleTitle("Remote Server v2.0 | Encrypted");
    printf(COLOR_CYAN "=====================================================\n");
    printf("             REMOTE CONTROL SERVER v2.0\n");
    printf("               Secure XOR Encrypted Tunnel\n");
    printf("=====================================================\n" COLOR_RESET);
}

static void HandleClientConnection(SOCKET client_socket) {
    if (!AuthenticateClient(client_socket)) {
        printf(COLOR_RED "[!] Client authentication failed\n" COLOR_RESET);
        return;
    }

    printf(COLOR_GREEN "[+] Client authenticated successfully\n" COLOR_RESET);
    char command_buffer[BUFFER_SIZE] = { 0 };

    while (1) {
        memset(command_buffer, 0, sizeof(command_buffer));
        int recv_len = recv(client_socket, command_buffer, BUFFER_SIZE, 0);

        if (recv_len <= 0) {
            printf(COLOR_RED "[-] Client disconnected\n" COLOR_RESET);
            break;
        }

        XorEncryptDecrypt(command_buffer, recv_len, ENCRYPT_KEY, KEY_LENGTH);

        if (strncmp(command_buffer, "CMD ", 4) == 0) {
            ExecuteSystemCommand(command_buffer + 4, command_buffer, BUFFER_SIZE);
        }
        else if (strncmp(command_buffer, "PS", 2) == 0) {
            ListAllProcesses(command_buffer);
        }
        else if (strncmp(command_buffer, "READ ", 5) == 0) {
            DWORD pid = 0;
            uintptr_t address = 0;
            int value = 0;

            if (sscanf(command_buffer + 5, "%d %llx", &pid, (unsigned long long*) & address) == 2) {
                ReadProcessMemorySafe(pid, (LPVOID)address, &value);
                snprintf(command_buffer, BUFFER_SIZE, "%d", value);
            }
            else {
                strcpy(command_buffer, "Invalid parameters - Usage: READ PID ADDR");
            }
        }
        else if (strncmp(command_buffer, "WRITE ", 6) == 0) {
            DWORD pid = 0;
            uintptr_t address = 0;
            int value = 0;

            if (sscanf(command_buffer + 6, "%d %llx %d", &pid, (unsigned long long*) & address, &value) == 3) {
                if (WriteProcessMemorySafe(pid, (LPVOID)address, value)) {
                    strcpy(command_buffer, "OK");
                }
                else {
                    strcpy(command_buffer, "Failed to write memory");
                }
            }
            else {
                strcpy(command_buffer, "Invalid parameters - Usage: WRITE PID ADDR VAL");
            }
        }
        else if (strncmp(command_buffer, "UPLOAD ", 7) == 0) {
            ReceiveFileFromClient(client_socket, command_buffer + 7);
            strcpy(command_buffer, "Upload completed successfully");
        }
        else if (strncmp(command_buffer, "DOWNLOAD ", 9) == 0) {
            SendFileToClient(client_socket, command_buffer + 9);
            strcpy(command_buffer, "Download completed successfully");
        }
        else {
            strcpy(command_buffer, "Unknown command - Type 'help' for available commands");
        }

        int response_len = strlen(command_buffer);
        XorEncryptDecrypt(command_buffer, response_len, ENCRYPT_KEY, KEY_LENGTH);
        send(client_socket, command_buffer, response_len, 0);
    }
}

static int InitializeWinsock(void) {
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        printf(COLOR_RED "Winsock initialization failed: %d\n" COLOR_RESET, result);
        return 0;
    }
    return 1;
}

static void CleanupServerResources(SOCKET server_socket) {
    if (server_socket != INVALID_SOCKET) {
        closesocket(server_socket);
    }
    WSACleanup();
}

int main(void) {
    if (!InitializeWinsock()) {
        return 1;
    }

    ShowServerLogo();

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf(COLOR_RED "Socket creation failed: %d\n" COLOR_RESET, WSAGetLastError());
        CleanupServerResources(server_socket);
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf(COLOR_RED "Bind failed: %d\n" COLOR_RESET, WSAGetLastError());
        CleanupServerResources(server_socket);
        return 1;
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf(COLOR_RED "Listen failed: %d\n" COLOR_RESET, WSAGetLastError());
        CleanupServerResources(server_socket);
        return 1;
    }

    printf(COLOR_GREEN "[*] Server listening on port %d...\n" COLOR_RESET, SERVER_PORT);

    while (1) {
        SOCKET client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == INVALID_SOCKET) {
            printf(COLOR_RED "Accept failed: %d\n" COLOR_RESET, WSAGetLastError());
            continue;
        }

        printf(COLOR_YELLOW "[*] New client connection accepted\n" COLOR_RESET);
        HandleClientConnection(client_socket);
        closesocket(client_socket);
    }

    CleanupServerResources(server_socket);
    return 0;
}