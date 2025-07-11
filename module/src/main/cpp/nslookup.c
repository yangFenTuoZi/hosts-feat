#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

// DNS头部结构
typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char z :3;
    unsigned char ra :1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNS_HEADER;

// DNS查询结构
typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;

// DNS资源记录结构
typedef struct {
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
} R_DATA;

// DNS响应结构
typedef struct {
    unsigned char *name;
    R_DATA *resource;
    unsigned char *rdata;
} RES_RECORD;

// 函数声明
void prepare_dns_query(unsigned char *buffer, const char *domain, int qtype);
int parse_dns_response(unsigned char *buffer, int len, char **results, int max_results);
void change_to_dns_name_format(unsigned char *dns, const char *host);
int send_dns_query(const char *dns_server, int dns_port, unsigned char *query, int query_len,
                   unsigned char *response, int response_len, int timeout);
int is_ipv6(const char *ip);

JNIEXPORT jobjectArray JNICALL Java_yangfentuozi_hostsfeat_NSLookup_lookup(
        JNIEnv *env, jobject obj, jstring domain, jstring dns, jint timeout) {

    const char *domain_str = (*env)->GetStringUTFChars(env, domain, 0);
    const char *dns_str = (*env)->GetStringUTFChars(env, dns, 0);

    unsigned char query[1024], response[4096];
    char *results[32]; // 最多存储32个结果
    int result_count = 0;

    // 查询A记录
    prepare_dns_query(query, domain_str, 1); // 1表示A记录
    int len = send_dns_query(dns_str, 53, query, sizeof(query), response, sizeof(response), timeout);
    if (len > 0) {
        result_count = parse_dns_response(response, len, results, 32);
    }

    // 查询AAAA记录
    prepare_dns_query(query, domain_str, 28); // 28表示AAAA记录
    len = send_dns_query(dns_str, 53, query, sizeof(query), response, sizeof(response), timeout);
    if (len > 0) {
        result_count += parse_dns_response(response, len, results + result_count, 32 - result_count);
    }

    // 创建Java字符串数组
    jobjectArray ret = (*env)->NewObjectArray(env, result_count,
                                              (*env)->FindClass(env, "java/lang/String"), (*env)->NewStringUTF(env, ""));

    for (int i = 0; i < result_count; i++) {
        (*env)->SetObjectArrayElement(env, ret, i, (*env)->NewStringUTF(env, results[i]));
        free(results[i]);
    }

    (*env)->ReleaseStringUTFChars(env, domain, domain_str);
    (*env)->ReleaseStringUTFChars(env, dns, dns_str);

    return ret;
}

// 准备DNS查询报文
void prepare_dns_query(unsigned char *buffer, const char *domain, int qtype) {
    DNS_HEADER *dns = (DNS_HEADER *)buffer;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0; // 查询
    dns->opcode = 0; // 标准查询
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1; // 递归查询
    dns->ra = 0;
    dns->z = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1); // 1个问题
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    unsigned char *qname = buffer + sizeof(DNS_HEADER);
    change_to_dns_name_format(qname, domain);

    QUESTION *qinfo = (QUESTION *)(qname + strlen((const char *)qname) + 1);
    qinfo->qtype = htons(qtype); // A或AAAA记录
    qinfo->qclass = htons(1); // IN
}

// 转换域名格式为DNS格式
void change_to_dns_name_format(unsigned char *dns, const char *host) {
    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

// 发送DNS查询并接收响应
int send_dns_query(const char *dns_server, int dns_port, unsigned char *query, int query_len,
                   unsigned char *response, int response_len, int timeout) {
    int sockfd;
    struct sockaddr_in servaddr;
    struct sockaddr_in6 servaddr6;
    struct timeval tv;

    // 设置超时
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    // 创建socket
    if (is_ipv6(dns_server)) {
        sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            return -1;
        }

        memset(&servaddr6, 0, sizeof(servaddr6));
        servaddr6.sin6_family = AF_INET6;
        servaddr6.sin6_port = htons(dns_port);
        inet_pton(AF_INET6, dns_server, &servaddr6.sin6_addr);

        // 设置超时
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

        // 发送查询
        if (sendto(sockfd, query, query_len, 0, (struct sockaddr *)&servaddr6, sizeof(servaddr6)) < 0) {
            close(sockfd);
            return -1;
        }
    } else {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            return -1;
        }

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(dns_port);
        inet_pton(AF_INET, dns_server, &servaddr.sin_addr);

        // 设置超时
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

        // 发送查询
        if (sendto(sockfd, query, query_len, 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
            close(sockfd);
            return -1;
        }
    }

    // 接收响应
    int len = recv(sockfd, response, response_len, 0);
    close(sockfd);

    return len;
}

// 解析DNS响应
int parse_dns_response(unsigned char *buffer, int len, char **results, int max_results) {
    DNS_HEADER *dns = (DNS_HEADER *)buffer;
    unsigned char *reader = buffer + sizeof(DNS_HEADER);
    int i, j, result_count = 0;

    // 跳过问题部分
    for (i = 0; i < htons(dns->qdcount); i++) {
        while (*reader != 0) {
            if (*reader >= 192) { // 压缩指针
                reader += 2;
                break;
            }
            reader += *reader + 1;
        }
        reader += 5; // 跳过类型和类
    }

    // 解析回答部分
    for (i = 0; i < htons(dns->ancount) && result_count < max_results; i++) {
        // 跳过名称
        while (*reader != 0) {
            if (*reader >= 192) { // 压缩指针
                reader += 2;
                break;
            }
            reader += *reader + 1;
        }

        R_DATA *resource = (R_DATA *)reader;
        reader += sizeof(R_DATA);

        if (htons(resource->type) == 1) { // A记录
            struct in_addr addr;
            addr.s_addr = *((unsigned int *)reader);
            char *ip = inet_ntoa(addr);
            results[result_count] = strdup(ip);
            result_count++;
            reader += htons(resource->data_len);
        } else if (htons(resource->type) == 28) { // AAAA记录
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, reader, ipv6, INET6_ADDRSTRLEN);
            results[result_count] = strdup(ipv6);
            result_count++;
            reader += htons(resource->data_len);
        } else {
            reader += htons(resource->data_len);
        }
    }

    return result_count;
}

// 检查是否是IPv6地址
int is_ipv6(const char *ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip, &(sa.sin6_addr)) != 0;
}