//
// Created by L.Laddie on 2017/5/11.
//

#ifndef DNS_SERVER_DNS_H
#define DNS_SERVER_DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <process.h>
#include <time.h>

#include <winsock2.h>
#include <inaddr.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_THREAD 100
#define MAX_DNS 4000    // 限制本地最大dns缓存
#define MAX_URL 80      // 限制最大域名长度
#define MAX_UDP 1500    // 限制UDP最大报文长度
#define MAX_IP 20       // 限制最大查询到的ip数
#define RECURSIVE_EN 1  // 服务端支持递归查询
#define LIVE_TIME 1000  // 存活时间：1000s
#define RELAY_TIME 3000    // 中继查询等待时间

#define FLAG_QR(flag) ((flag)>>15)&1
#define FLAG_TC(flag) ((flag)>>9)&1
#define FLAG_RD(flag) ((flag)>>8)&1
#define FLAG_RA(flag) ((flag)>>7)&1

// 查询的资源记录类型
enum QueryType {
    A = 0x01, //指定计算机 IP 地址。
    NS = 0x02, //指定用于命名区域的 DNS 名称服务器。
    MD = 0x03, //指定邮件接收站（此类型已经过时了，使用MX代替）
    MF = 0x04, //指定邮件中转站（此类型已经过时了，使用MX代替）
    CNAME = 0x05, //指定用于别名的规范名称。
    SOA = 0x06, //指定用于 DNS 区域的“起始授权机构”。
    MB = 0x07, //指定邮箱域名。
    MG = 0x08, //指定邮件组成员。
    MR = 0x09, //指定邮件重命名域名。
    NULL_T = 0x0A, //指定空的资源记录
    WKS = 0x0B, //描述已知服务。
    PTR = 0x0C, //如果查询是 IP 地址，则指定计算机名；否则指定指向其它信息的指针。
    HINFO = 0x0D, //指定计算机 CPU 以及操作系统类型。
    MINFO = 0x0E, //指定邮箱或邮件列表信息。
    MX = 0x0F, //指定邮件交换器。
    TXT = 0x10, //指定文本信息。
    UINFO = 0x64, //指定用户信息。
    UID = 0x65, //指定用户标识符。
    GID = 0x66, //指定组名的组标识符。
    ANY_T = 0xFF, //指定所有数据类型。
    AAAA = 0x1c
};

// 指定信息的协议组
enum QueryClass
{
    INET = 0x01, //指定 Internet 类别。
    CSNET = 0x02, //指定 CSNET 类别。（已过时）
    CHAOS = 0x03, //指定 Chaos 类别。
    HESIOD = 0x04,//指定 MIT Athena Hesiod 类别。
    ANY_C = 0xFF //指定任何以前列出的通配符。
};

// DNS标志位
struct dns_flag {
    u_char rd :1;     // 期望递归
    u_char tc :1;     // 可截断
    u_char aa :1;     // 授权回答
    u_char opcode :4; // 查询类型：标准查询、反向查询、服务器查询
    u_char qr :1;     // 查询报文、响应报文
    u_char rcode :4;  // 0表示无差错，1表示格式错误，2服务器错误，3名字有错，4服务器不支持，5拒绝
    u_char zero :3;   // 必须为0
    u_char ra :1;     // 可用递归
};


// DNS报文前12字节
struct dns_header {
    u_short id;         // 标识符
    struct dns_flag flag;       // 标志位 [QR(4), OPCODE(4), AA(1), TC(2), RD(1), RA(1), ZERO(3)]
    u_short que_cnt;    // 问题数(实际中始终为1，防止DDoS攻击)
    u_short ans_cnt;    // 回答数
    u_short auth_cnt;   // 授权记录数
    u_short add_cnt;    // 额外记录数
};

// DNS查询报名部分结构
struct dns_query_type {
    u_short type;       // 查询类型 (A-1, NS-2, CNAME-5, PTR-12, HINFO-13,MX-15)
    u_short class_type; // 查询类(默认1表示互联网数据)
};

// DNS资源记录格式(用于回答、授权记录、额外记录)
struct dns_rr_type {
    u_short type;       // 查询类型
    u_short class_type; // 查询类
    u_int live_time;    // 生存时间
    u_short data_len;   // 资源数据长度
    u_short no_use;     // x86自动对齐到32位，这实际是资源数据的一部分
};

// 线程参数结构体
struct thread_data{
    char rev_data[MAX_UDP];
    int rev_len;
    struct sockaddr_in client_addr;
    SOCKET ser_skt;
};

void init_cache();

u_short query_ip(char *name, u_int *ans);
u_int make_error_pkg(char *rtn_buf, u_char rcode);
u_int make_response(char *rtn_buf, u_int *ip, u_short nip);
u_int relay_dns(char *raw_buf, int len, u_short id, char *rtn_buf);

int ddprintf(const char * format, ...);
int dprintf(const char * format, ...);
int lprintf(const char * format, ...);

#endif //DNS_SERVER_DNS_H
