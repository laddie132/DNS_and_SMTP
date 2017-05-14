#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <conio.h>

#include "base64.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_TCP 1500
#define MAX_NAME 128
#define MAX_BODY 1400

char rev_buf[MAX_TCP] = {0};
char send_buf[MAX_TCP] = {0};

// 打印帮助信息
void print_help() {
    printf("*************************************************************\n");
    printf("*                      SMTP CLIENT                          *\n");
    printf("*************************************************************\n");
    printf("smtp client to send emails\n");
    printf("Usage: smtp_clent.exe\n");
    printf("Designed by: Liu Han, liuhan132@foxmail.com\n\n");
}

// 获取邮件地址对应smtp服务器
void get_server(const char *email_addr, char *smtp_server)
{
    char addr[MAX_NAME];
    strcpy(addr, email_addr);
    char *suffix = strtok(addr, "@");

    if(suffix == NULL){
        fprintf(stderr, "Email To address error!\n");
        exit(1);
    }

    suffix = &suffix[strlen(suffix)+1];

    strcpy(smtp_server, "smtp.");
    strcat(smtp_server, suffix);
}

// 创建socket并连接到服务器
SOCKET conn_server(struct sockaddr* addr)
{
    SOCKET sockfd;
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        fprintf(stderr, "Socket open error\n");
        exit(1);
    }
    if(connect(sockfd, addr, sizeof(struct sockaddr)) < 0)
    {
        fprintf(stderr, "Socket connect error\n");
        exit(1);
    }
    return sockfd;
}

// 从文件读取邮件内容
void read_body(char *filename, char *body)
{
    FILE *fp = fopen(filename, "r");
    if(fp == NULL){
        fprintf(stderr, "File \"%s\" not exists\n", filename);
        exit(1);
    }

    memset(body, 0, MAX_BODY);
    while(!feof(fp)){
        fgets(body + strlen(body), MAX_BODY, fp);
        sprintf(body + strlen(body) - 1, "\r\n");
    }
    fclose(fp);
}

// 特殊的读取方式，屏幕显示星号
void get_passwd(char *passwd)
{
    char c;
    int i = 0;
    int len = MAX_NAME-1;

    while ((c= (char) getch()) != '\r')
    {
        passwd[i] = c;
        putchar('*');
        i++;
        if (i >= len)
            break;
    }
    putchar('\n');
    passwd[i] = 0;
}


// 向服务器发送指令
void send_ser(SOCKET sockfd)
{
    send(sockfd, send_buf, (int) strlen(send_buf), 0);
    memset(rev_buf, 0, MAX_TCP);
    recv(sockfd, rev_buf, MAX_TCP, 0);
}

// 开始发送邮件
void send_email() {
    char login[MAX_NAME];       // 登录名
    char pawd[MAX_NAME];        // 密码
    char send_addr[MAX_NAME];   // 发件人
    char rev_addr[MAX_NAME];    // 收件人
    char smtp_server[MAX_NAME]; // 邮箱SMTP服务器
    char body_file[MAX_PATH];   // 邮件内容（文件名）
    char body[MAX_BODY];        // 邮件内容

    // 用户交互
    printf("Login:");
    scanf("%s", login);
    printf("Password:");
    get_passwd(pawd);

    printf("Mail from(default login):");
    fflush(stdin);
    gets(send_addr);
    if(send_addr[0] == 0)
        strcpy(send_addr, login);

    printf("Mail to(default login):");
    fflush(stdin);
    gets(rev_addr);
    if(rev_addr[0] == 0)
        strcpy(rev_addr, login);

    printf("Email body(default \"email.txt\"):");
    fflush(stdin);
    gets(body_file);
    if(body_file[0] == 0)
        sprintf(body_file, "email.txt");

    get_server(login, smtp_server);

    // 建立socket连接
    struct sockaddr_in ser_addr = {0};
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port   = htons(25);
    struct hostent* hptr = gethostbyname(smtp_server);
    memcpy(&ser_addr.sin_addr.S_un.S_addr, hptr->h_addr_list[0], (size_t) hptr->h_length);
    printf("SMTP server: %s, %d.%d.%d.%d\n\n",
           smtp_server,
           ser_addr.sin_addr.S_un.S_un_b.s_b1,
           ser_addr.sin_addr.S_un.S_un_b.s_b2,
           ser_addr.sin_addr.S_un.S_un_b.s_b3,
           ser_addr.sin_addr.S_un.S_un_b.s_b4);

    // 无响应2s重新连接
    SOCKET sockfd = conn_server((struct sockaddr*)&ser_addr);
    while(recv(sockfd, rev_buf, MAX_TCP, 0) == 0)
    {
        printf("Reconnecting...\n");
        Sleep(2000);
        sockfd = conn_server((struct sockaddr*)&ser_addr);
        memset(rev_buf, 0, MAX_TCP);
    }

    printf("S(Connect): %s", rev_buf);

    // EHLO
    sprintf(send_buf, "EHLO L.LADDIE\r\n");
    send_ser(sockfd);
    printf("C(EHLO): %s", send_buf);
    printf("S(EHLO): %s", rev_buf);

    // AUTH LOGIN
    sprintf(send_buf, "AUTH LOGIN\r\n");
    send_ser(sockfd);
    printf("C(AUTH): %s", send_buf);
    printf("S(AUTH): %s", rev_buf);

    // USERNAME
    char login_base64[MAX_NAME] = {0};
    EncodeBase64(login_base64, login, (int) strlen(login));
    sprintf(send_buf, "%s\r\n", login_base64);
    send_ser(sockfd);
    printf("C(LOGIN): %s", send_buf);
    printf("S(LOGIN): %s", rev_buf);

    char *prefix = strtok(rev_buf, " ");
    if(!strcmp(prefix, "535")){
        fprintf(stderr, "No user\n");
        closesocket(sockfd);
        exit(1);
    }

    // PASSWD
    char passwd_base64[MAX_NAME] = {0};
    EncodeBase64(passwd_base64, pawd, (int) strlen(pawd));
    sprintf(send_buf, "%s\r\n", passwd_base64);
    send_ser(sockfd);
    printf("C(PASSWD): %s", send_buf);
    printf("S(PASSWD): %s", rev_buf);

    prefix = strtok(rev_buf, " ");
    if(!strcmp(prefix, "535")){
        fprintf(stderr, "Passwd error\n");
        closesocket(sockfd);
        exit(1);
    }

    // MAIL FROM
    sprintf(send_buf, "MAIL FROM: <%s>\r\n", send_addr);
    send_ser(sockfd);
    printf("C(MAIL FROM): %s", send_buf);
    printf("S(MAIL FROM): %s", rev_buf);

    // RCPT TO
    sprintf(send_buf, "RCPT TO: <%s>\r\n", rev_addr);
    send_ser(sockfd);
    printf("C(MAIL TO): %s", send_buf);
    printf("S(MAIL TO): %s", rev_buf);

    // DATA
    sprintf(send_buf, "DATA\r\n");
    send_ser(sockfd);
    printf("C(DATA): %s", send_buf);
    printf("S(DATA): %s", rev_buf);

    // BODY
    read_body(body_file, body);
    sprintf(send_buf, "%s\r\n.\r\n", body);
    send_ser(sockfd);
    printf("C(BODY): %s", send_buf);
    printf("S(BODY): %s", rev_buf);

    // QUIT
    sprintf(send_buf, "QUIT\r\n");
    send_ser(sockfd);
    printf("C(QUIT): %s", send_buf);
    printf("S(QUIT): %s", rev_buf);

    // 关闭socket
    closesocket(sockfd);
}

int main() {
    print_help();

    // 初始化WSA
    WSADATA wsadata;
    WORD sock_ver = MAKEWORD(2, 2);
    if (WSAStartup(sock_ver, &wsadata) != 0) {
        fprintf(stderr, "WSA start error!\n");
        return 1;
    }

    // 开始发送邮件
    send_email();

    // 关闭WSA库
    WSACleanup();
    return 0;
}