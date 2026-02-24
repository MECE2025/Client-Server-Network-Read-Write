#define _CRT_SECURE_NO_WARNINGS 1
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"user32.lib")

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

static SOCKET g_ClientSocket = INVALID_SOCKET;

static void ClearConsole(void);
static void XorEncryptDecrypt(char* data, int data_len, const char* key, int key_len);
static void ShowLoadingAnimation(const char* message);
static void ShowProgressBar(void);
static void ShowFullLogo(void);
static void ShowHelpMenu(void);
static int PerformLogin(void);
static void DownloadFile(const char* file_path);
static void UploadFile(const char* file_path);
static int InitializeWinsock(void);
static void CleanupResources(void);

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

static void ShowLoadingAnimation(const char* message) {
    printf(COLOR_CYAN "%s ", message);
    for (int i = 0; i < 3; i++) {
        printf(".");
        fflush(stdout);
        Sleep(300);
    }
    printf(" " COLOR_RESET);
}

static void ShowProgressBar(void) {
    printf(COLOR_GREEN "[");
    for (int i = 0; i < 20; i++) {
        printf("=");
        fflush(stdout);
        Sleep(50);
    }
    printf("] 100%%\n" COLOR_RESET);
}

static void ShowFullLogo(void) {
    ClearConsole();
    SetConsoleTitle("Remote Client v2.0 | Encrypted");
    printf(COLOR_CYAN "=====================================================\n");
    printf("               REMOTE CLIENT v2.0\n");
    printf("            Secure XOR Encrypted Communication\n");
    printf("=====================================================\n" COLOR_RESET);
}

static void ShowHelpMenu(void) {
    ShowFullLogo();
    printf(COLOR_YELLOW "\n=== Supported Commands ===\n" COLOR_RESET);
    printf("  CMD [command]   - Execute system command\n");
    printf("  PS              - List all running processes\n");
    printf("  READ PID ADDR   - Read 4-byte memory from target process\n");
    printf("  WRITE PID ADDR VAL - Write 4-byte value to process memory\n");
    printf("  UPLOAD [file]   - Upload local file to server\n");
    printf("  DOWNLOAD [file] - Download file from server\n");
    printf("  help            - Show this help menu\n");
    printf("  exit            - Disconnect and exit\n");
    printf(COLOR_PURPLE "Default Credentials: admin / 123456\n" COLOR_RESET);
}

static int PerformLogin(void) {
    char username[LOGIN_BUF_SIZE] = { 0 };
    char password[LOGIN_BUF_SIZE] = { 0 };

    ShowFullLogo();
    printf(COLOR_GREEN "[*] Authentication Required\n" COLOR_RESET);
    printf("Username: ");
    if (scanf("%63s", username) != 1) {
        printf(COLOR_RED "Input error!\n" COLOR_RESET);
        return 0;
    }
    printf("Password: ");
    if (scanf("%63s", password) != 1) {
        printf(COLOR_RED "Input error!\n" COLOR_RESET);
        return 0;
    }
    while (getchar() != '\n');

    ShowLoadingAnimation("Authenticating");

    XorEncryptDecrypt(username, LOGIN_BUF_SIZE, ENCRYPT_KEY, KEY_LENGTH);
    XorEncryptDecrypt(password, LOGIN_BUF_SIZE, ENCRYPT_KEY, KEY_LENGTH);

    if (send(g_ClientSocket, username, LOGIN_BUF_SIZE, 0) == SOCKET_ERROR ||
        send(g_ClientSocket, password, LOGIN_BUF_SIZE, 0) == SOCKET_ERROR) {
        printf(COLOR_RED "Network error during authentication!\n" COLOR_RESET);
        return 0;
    }

    char auth_result[10] = { 0 };
    int recv_len = recv(g_ClientSocket, auth_result, sizeof(auth_result) - 1, 0);
    if (recv_len <= 0 || strcmp(auth_result, "OK") != 0) {
        printf(COLOR_RED "Authentication Failed!\n" COLOR_RESET);
        return 0;
    }

    printf(COLOR_GREEN "Authentication Successful!\n" COLOR_RESET);
    ShowProgressBar();
    Sleep(500);
    return 1;
}

static void DownloadFile(const char* file_path) {
    if (file_path == NULL || strlen(file_path) == 0) {
        printf(COLOR_RED "Invalid file path!\n" COLOR_RESET);
        return;
    }

    printf(COLOR_YELLOW "[*] Downloading file: %s\n" COLOR_RESET, file_path);

    char server_response[3] = { 0 };
    int recv_len = recv(g_ClientSocket, server_response, 2, 0);
    if (recv_len <= 0 || strcmp(server_response, "OK") != 0) {
        printf(COLOR_RED "Download failed - Server rejected request\n" COLOR_RESET);
        return;
    }

    FILE* file_handle = fopen(file_path, "wb");
    if (file_handle == NULL) {
        printf(COLOR_RED "Failed to create local file: %s\n" COLOR_RESET, file_path);
        return;
    }

    char file_buffer[FILE_BUF_SIZE] = { 0 };
    int bytes_received = 0;
    while ((bytes_received = recv(g_ClientSocket, file_buffer, FILE_BUF_SIZE, 0)) > 0) {
        XorEncryptDecrypt(file_buffer, bytes_received, ENCRYPT_KEY, KEY_LENGTH);
        fwrite(file_buffer, 1, bytes_received, file_handle);
        memset(file_buffer, 0, FILE_BUF_SIZE);
    }

    fclose(file_handle);
    printf(COLOR_GREEN "[+] File downloaded successfully: %s\n" COLOR_RESET, file_path);
    ShowProgressBar();
}

static void UploadFile(const char* file_path) {
    if (file_path == NULL || strlen(file_path) == 0) {
        printf(COLOR_RED "Invalid file path!\n" COLOR_RESET);
        return;
    }

    printf(COLOR_YELLOW "[*] Uploading file: %s\n" COLOR_RESET, file_path);

    FILE* file_handle = fopen(file_path, "rb");
    if (file_handle == NULL) {
        printf(COLOR_RED "Failed to open file: %s\n" COLOR_RESET, file_path);
        return;
    }

    char file_buffer[FILE_BUF_SIZE] = { 0 };
    int bytes_read = 0;
    while ((bytes_read = fread(file_buffer, 1, FILE_BUF_SIZE, file_handle)) > 0) {
        XorEncryptDecrypt(file_buffer, bytes_read, ENCRYPT_KEY, KEY_LENGTH);
        send(g_ClientSocket, file_buffer, bytes_read, 0);
        memset(file_buffer, 0, FILE_BUF_SIZE);
    }

    fclose(file_handle);
    printf(COLOR_GREEN "[+] File uploaded successfully: %s\n" COLOR_RESET, file_path);
    ShowProgressBar();
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

static void CleanupResources(void) {
    if (g_ClientSocket != INVALID_SOCKET) {
        closesocket(g_ClientSocket);
    }
    WSACleanup();
}

int main(void) {
    if (!InitializeWinsock()) {
        return 1;
    }

    ShowFullLogo();
    char server_ip[64] = { 0 };
    int server_port = 0;

    printf(COLOR_GREEN "[*] Server Connection Setup\n" COLOR_RESET);
    printf("Server IP: ");
    fgets(server_ip, sizeof(server_ip), stdin);
    server_ip[strcspn(server_ip, "\n")] = '\0';

    printf("Server Port: ");
    while (scanf("%d", &server_port) != 1 || server_port < 1 || server_port > 65535) {
        printf(COLOR_RED "Invalid port! Please enter a number between 1-65535: " COLOR_RESET);
        while (getchar() != '\n');
    }
    getchar();

    g_ClientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ClientSocket == INVALID_SOCKET) {
        printf(COLOR_RED "Socket creation failed: %d\n" COLOR_RESET, WSAGetLastError());
        CleanupResources();
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    ShowLoadingAnimation("Connecting to server");
    if (connect(g_ClientSocket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf(COLOR_RED "Connection failed: %d\n" COLOR_RESET, WSAGetLastError());
        CleanupResources();
        return 1;
    }

    printf(COLOR_GREEN "Connected to server successfully!\n" COLOR_RESET);
    ShowProgressBar();
    Sleep(500);

    if (!PerformLogin()) {
        printf(COLOR_RED "[!] Authentication failed - Exiting\n" COLOR_RESET);
        Sleep(2000);
        CleanupResources();
        return 1;
    }

    ShowHelpMenu();
    char command_buffer[BUFFER_SIZE] = { 0 };

    while (1) {
        printf(COLOR_BLUE "\n> " COLOR_RESET);
        fgets(command_buffer, sizeof(command_buffer), stdin);
        command_buffer[strcspn(command_buffer, "\n")] = '\0';

        if (strcmp(command_buffer, "exit") == 0) {
            break;
        }

        if (strcmp(command_buffer, "help") == 0) {
            ShowHelpMenu();
            continue;
        }

        if (strlen(command_buffer) == 0) {
            continue;
        }

        int cmd_len = strlen(command_buffer);
        XorEncryptDecrypt(command_buffer, cmd_len, ENCRYPT_KEY, KEY_LENGTH);
        send(g_ClientSocket, command_buffer, cmd_len, 0);

        if (strncmp(command_buffer, "DOWNLOAD ", 9) == 0) {
            DownloadFile(command_buffer + 9);
            continue;
        }
        if (strncmp(command_buffer, "UPLOAD ", 7) == 0) {
            UploadFile(command_buffer + 7);
            continue;
        }

        char response_buffer[BUFFER_SIZE] = { 0 };
        int response_len = recv(g_ClientSocket, response_buffer, sizeof(response_buffer), 0);
        if (response_len > 0) {
            XorEncryptDecrypt(response_buffer, response_len, ENCRYPT_KEY, KEY_LENGTH);
            printf(COLOR_GREEN "\n--- Server Response ---\n" COLOR_RESET);
            printf("%s\n", response_buffer);
        }
        else if (response_len == 0) {
            printf(COLOR_RED "[!] Server disconnected\n" COLOR_RESET);
            break;
        }
        else {
            printf(COLOR_RED "[!] Receive error: %d\n" COLOR_RESET, WSAGetLastError());
            break;
        }
    }

    CleanupResources();
    printf(COLOR_YELLOW "[*] Disconnected - Exiting client\n" COLOR_RESET);
    Sleep(1000);
    return 0;
}