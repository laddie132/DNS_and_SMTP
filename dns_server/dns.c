//
// Created by L.Laddie on 2017/5/11.
//

#include "dns.h"


int DEBUG_LEVEL = 0;
char ADDR[20] = "0.0.0.0";
u_short PORT = 53;
char LOCALCACHE[MAX_PATH] = "dnsrelay.txt";
char REMOTESER[20] = "114.114.114.114";
u_short REMOTEPORT = 53;

int n_dns = 0;
char dns_url[MAX_DNS][MAX_URL];
char dns_ip[MAX_DNS][20];

int relay_id = 0;

CRITICAL_SECTION lock;

// 初始化本地dns缓存数据
void init_cache()
{
    ddprintf("Loading dns cache from file %s...\n", LOCALCACHE);

    FILE *fp = fopen(LOCALCACHE, "r");
    if(fp == NULL){
        fprintf(stderr, "File read error!\n");
        exit(1);
    }

    char tmp_line[MAX_URL+20];
    while(!feof(fp)){
        fgets(tmp_line, MAX_URL+20, fp);

        if(tmp_line[0] != '#' && tmp_line[0] != '\n')
        {
            sscanf(tmp_line, "%s %s\n", dns_ip[n_dns], dns_url[n_dns]);
            ddprintf("%s %s\n", dns_ip[n_dns], dns_url[n_dns]);
            n_dns++;
        }
    }

    fclose(fp);
}

// 解析dns查询
u_int handle_query(char *raw_buf, int len, char *rtn_buf) {
    // 直接拷贝头部和查询
    memcpy(rtn_buf, raw_buf, 12 + strlen(&raw_buf[12]) + 1 + sizeof(struct dns_query_type));

    struct dns_header *buf_h = (struct dns_header *) raw_buf;
    raw_buf += 12;

    struct dns_query_type *buf_qh = (struct dns_query_type*)(raw_buf + strlen(raw_buf) + 1);

    // 不支持的格式查询
    if (ntohs(buf_h->que_cnt) != 1 || (ntohs(buf_qh->type) != A && ntohs(buf_qh->type) != AAAA)
        || ntohs(buf_qh->class_type) != INET) {

        lprintf("Query %x, not supported format\n", ntohs(buf_h->id));
        return make_error_pkg(rtn_buf, 4);
    }

    // 获取查询名
    char name[MAX_URL];
    int i = 0, w = 0;
    while (i < strlen(raw_buf)) {
        int cur_len = raw_buf[i++];
        for (int j = 0; j < cur_len; j++)
            name[w++] = raw_buf[i + j];

        i += cur_len;
        name[w++] = '.';
    }
    name[w - 1] = 0;

    // AAAA类查询（ipv6地址全部中继查询）
    if(ntohs(buf_qh->type) == AAAA) {
        dprintf("Query %x, type AAAA, url \"%s\"\n", ntohs(buf_h->id), name);

        u_int rtn = relay_dns(raw_buf-12, len, ntohs(buf_h->id), rtn_buf);
        if(!rtn)
            return make_response(rtn_buf, 0, 0);
        return rtn;
    }

    // A类查询（ipv4地址）
    u_int ip[MAX_IP];
    u_short nip = query_ip(name, ip);

    if(nip == 0)        // 不存在的url地址(中继查询)
    {
        dprintf("Query %x, type A, local none url \"%s\"\n", ntohs(buf_h->id), name);

        u_int rtn = relay_dns(raw_buf-12, len, ntohs(buf_h->id), rtn_buf);
        if(!rtn)
            return make_error_pkg(rtn_buf, 3);
        return rtn;
    }
    else if(nip == 1 && ip[0] == 0)     // 一个被禁止的url地址
    {
        dprintf("Query %x, type A, forbidden url \"%s\"\n", ntohs(buf_h->id), name);
        return make_error_pkg(rtn_buf, 3);
    }

    // 输出提示
    char tmp_str[50] = {0};
    for(int j = 0; j < nip; j++)
    {
        char ip_str[20];
        sprintf(ip_str, "%u.%u.%u.%u ", ((u_char*)&ip)[3], ((u_char*)&ip)[2], ((u_char*)&ip)[1], ((u_char*)&ip)[0]);
        strcat(tmp_str, ip_str);
    }
    dprintf("Query %x, type A, url \"%s\", answer ip %s\n", ntohs(buf_h->id), name, tmp_str);

    return make_response(rtn_buf, ip, nip);
}

// 中继查询
u_int relay_dns(char *raw_buf, int len, u_short id, char *rtn_buf)
{
    // 创建套接字到中继服务器
    struct sockaddr_in server;
    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(REMOTEPORT);
    server.sin_addr.s_addr = inet_addr(REMOTESER);

    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        lprintf("Query %x socket failed\n", id);
        return 0;
    }

    // 设置阻塞时间
    int timeout = RELAY_TIME;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));

    // 转换消息id
    char *buf = (char *)malloc((size_t) (len + 1));
    memcpy(buf, raw_buf, (size_t) len);

    struct dns_header *h = (struct dns_header*)buf;
    h->id = htons((u_short) (++relay_id % (1<<16)));

    ddprintf("Query %x to relay %x\n", id, ntohs(h->id));

    // 中继查询
    int ret = sendto(sockfd, buf, len, 0,(struct sockaddr *)&server, sizeof(struct sockaddr));
    if(ret < 0) {
        lprintf("Query %x sendto relay failed\n", id);
        closesocket(sockfd);
        return 0;
    }

    int addrlen = sizeof(struct sockaddr);
    ret = recvfrom(sockfd, rtn_buf, MAX_UDP, 0, (struct sockaddr *)&server, &addrlen);
    if(ret < 0) {
        lprintf("Query %x recvfrom relay failed\n", id);
        closesocket(sockfd);
        return 0;
    }

    // 转换消息id
    h = (struct dns_header*)rtn_buf;
    h->id = htons(id);

    closesocket(sockfd);
    free(buf);
    return (u_int)ret;
}


// 查询对应名的ip地址
u_short query_ip(char *name, u_int *ans)
{
    int p[4] = {16777216, 65536, 256, 1};   // ip地址每一位权重

    u_short nip = 0;
    for(int i = 0; i < n_dns; i++)
    {
        if(!strcmp(dns_url[i], name))
        {
            char tmp_ip[20];
            strcpy(tmp_ip, dns_ip[i]);
            ans[nip] = 0;

            int j = 0;
            char* result = strtok(tmp_ip, ".");
            while(result != NULL) {
                ans[nip] += atoi(result) * p[j++];
                result = strtok(NULL, ".");
            }

            nip++;
        }
    }

    return nip;
}

// 构造响应帧
u_int make_response(char *rtn_buf, u_int *ip, u_short nip)
{
    u_int rtn_len = 0;

    // 构造头部
    struct dns_header *rtn_header = (struct dns_header*)rtn_buf;

    rtn_header->flag.qr = 1;
    rtn_header->flag.ra = RECURSIVE_EN;
    rtn_header->ans_cnt = ntohs(nip);

    rtn_len += sizeof(struct dns_header);
    rtn_len += (int) (strlen(&rtn_buf[rtn_len]) + 1 + sizeof(struct dns_query_type));

    // 构造回答
    for(int i = 0; i < nip; i++)
    {
        u_char name[2] = {0xc0, 0x0c};
        memcpy(&rtn_buf[rtn_len], name, 2);
        rtn_len += 2;

        struct dns_rr_type *rr_t = (struct dns_rr_type*)(&rtn_buf[rtn_len]);
        rr_t->type = ntohs(A);
        rr_t->class_type = ntohs(INET);
        rr_t->live_time = ntohl(LIVE_TIME);
        rr_t->data_len = ntohs(4);
        rtn_len += sizeof(struct dns_rr_type)-2;

        *((u_int*)(&rtn_buf[rtn_len])) = ntohl(ip[i]);
        rtn_len += 4;
    }

    return rtn_len;
}


// 产生一个报错帧
u_int make_error_pkg(char *rtn_buf, u_char rcode)
{
    // 构造头部
    struct dns_header *rtn_header = (struct dns_header*)rtn_buf;

    rtn_header->flag.qr = 1;
    rtn_header->flag.rcode = rcode;
    rtn_header->flag.ra = RECURSIVE_EN;

    rtn_buf += 12;
    u_int tmp_len = (u_int) (strlen(rtn_buf) + 1 + sizeof(struct dns_query_type));

    return 12+tmp_len;
}

// 一个单独线程，负责处理查询并响应
unsigned int __stdcall run_thread(void* data)
{
    ddprintf("Thread %d start\n", GetCurrentThreadId());

    struct thread_data *arg = (struct thread_data*)data;
    char send_data[MAX_UDP];

    // 发送一个报文
    int send_len = handle_query(arg->rev_data, arg->rev_len, send_data);
    int recv_len2 = sendto(arg->ser_skt, send_data, send_len, 0,
                           (struct sockaddr *)&arg->client_addr, sizeof(struct sockaddr_in));
    if (recv_len2 < 0) {
        fprintf(stderr, "Sendto error!\n");
        return 0;
    }
    ddprintf("Send to %s\n", inet_ntoa(arg->client_addr.sin_addr));

    free(arg);

    return 0;
}


// 运行dns服务器
void run_server() {
    SOCKET ser_skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ser_skt == INVALID_SOCKET) {
        fprintf(stderr, "Socket error!\n");
        exit(1);
    }

    // 绑定socket到本地监听地址
    struct sockaddr_in ser_addr;
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.S_un.S_addr = inet_addr(ADDR);    // 设置监听地址
    ser_addr.sin_port = htons(PORT);
    if (bind(ser_skt, (struct sockaddr *) &ser_addr, sizeof(ser_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind error!\n");
        closesocket(ser_skt);
        exit(1);
    }

    // 处理客户端报文
    struct sockaddr_in client_addr;
    int cnt_addr = sizeof(client_addr);
    char rev_data[MAX_UDP];

    HANDLE thread_pool[MAX_THREAD] = {0};
    while (1) {
        ddprintf("Wait for recv\n");

        // 接收一个报文
        int recv_len = recvfrom(ser_skt, rev_data, MAX_UDP, 0, (struct sockaddr *) &client_addr, &cnt_addr);
        if (recv_len < 0) {
            fprintf(stderr, "Recvfrom error!\n");
            exit(1);
        }
        dprintf("Receive %s\n", inet_ntoa(client_addr.sin_addr));

        // 构造线程参数
        struct thread_data *arg = (struct thread_data *)malloc(sizeof(struct thread_data));
        memcpy(arg->rev_data, rev_data, MAX_UDP);
        memcpy(&arg->client_addr, &client_addr, sizeof(struct sockaddr_in));
        arg->rev_len = recv_len;
        arg->ser_skt = ser_skt;

        // 开启一个线程
        HANDLE hdle = (HANDLE)_beginthreadex(0, 0, run_thread, (void*)arg, 0, 0);
        if(hdle == NULL){
            fprintf(stderr, "Create thread error!\n");
            exit(1);
        }

        // 更新线程池
        DWORD exitCode;
        for(int i = 0; i < MAX_THREAD; i++) {
            if(thread_pool[i] && GetExitCodeThread(thread_pool[i], &exitCode) && exitCode != STILL_ACTIVE)
            {
                ddprintf("Thread %d closed\n", GetThreadId(thread_pool[i]));
                CloseHandle(thread_pool[i]);
                thread_pool[i] = 0;
            }

            if(thread_pool[i] == 0)
                thread_pool[i] = hdle;
        }
    }
}

// 格式化输出时间
void print_time()
{
    char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep);
    printf ("%d/%d/%d ", (1900+p->tm_year), (1+p->tm_mon), p->tm_mday);
    printf("%s %d:%d:%d, ", wday[p->tm_wday], p->tm_hour, p->tm_min, p->tm_sec);
}

// DEBUG_LEVEL = 2输出(带互斥锁)
int ddprintf(const char * format, ...)
{
    if(DEBUG_LEVEL < 2)
        return 0;

    EnterCriticalSection(&lock);

    printf("[DDEBUG]:");
    print_time();

    va_list vp;
    va_start(vp, format);
    int result = vprintf(format, vp);
    va_end(vp);

    LeaveCriticalSection(&lock);
    return result;
}

// DEBUG_LEVEL = 1输出(带互斥锁)
int dprintf(const char * format, ...)
{
    if(DEBUG_LEVEL < 1)
        return 0;

    EnterCriticalSection(&lock);

    printf("[DEBUG]:");
    print_time();

    va_list vp;
    va_start(vp, format);
    int result = vprintf(format, vp);
    va_end(vp);

    LeaveCriticalSection(&lock);
    return result;
}

// DEBUG_LEVEL = 0输出(带互斥锁)
int lprintf(const char * format, ...)
{
    EnterCriticalSection(&lock);

    printf("[INFO]:");
    print_time();

    va_list vp;
    va_start(vp, format);
    int result = vprintf(format, vp);
    va_end(vp);

    LeaveCriticalSection(&lock);
    return result;
}

// 打印帮助信息
void print_help() {
    printf("*************************************************************\n");
    printf("*                      DNS SERVER                           *\n");
    printf("*************************************************************\n");
    printf("Dns Server with local cache and relay\n");
    printf("Usage: dns_server.exe [-d | -dd] [dns-server-ipaddr] [filename]\n");
    printf("Designed by: Liu Han, liuhan132@foxmail.com\n");
}

int main(int argc, char *argv[]) {

    // 解析命令行参数
    int addr_fin = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h")) {
            print_help();
            return 0;
        }

        if (!strcmp(argv[i], "-dd"))
            DEBUG_LEVEL = 2;
        else if (!strcmp(argv[i], "-d"))
            DEBUG_LEVEL = 1;
        else if (!addr_fin) {
            strcpy(ADDR, argv[i]);
            addr_fin = 1;
        } else {
            strcpy(LOCALCACHE, argv[i]);
            break;
        }
    }

    print_help();
    printf("\nDNS server starting...\n");
    printf("Listen address: %s:%u\n", ADDR, PORT);
    printf("Local cache file: %s\n", LOCALCACHE);
    printf("Debug level: %d\n\n", DEBUG_LEVEL);

    // 初始化互斥锁
    InitializeCriticalSection(&lock);

    // 初始化本地缓存
    init_cache();

    // 初始化WSA
    WSADATA wsadata;
    WORD sock_ver = MAKEWORD(2, 2);
    if (WSAStartup(sock_ver, &wsadata) != 0) {
        fprintf(stderr, "WSA start error!\n");
        return 1;
    }

    run_server();

    // 关闭WSA库
    WSACleanup();

    // 销毁互斥锁
    DeleteCriticalSection(&lock);

    return 0;
}