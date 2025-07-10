#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <errno.h>

// ICMP包大小
#define PACKET_SIZE 64
// ICMP头大小
#define ICMP_HEADER_SIZE 8

// 计算校验和
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 发送和接收ICMP包
int ping_ipv4(const char *host, int timeout_ms) {
    int sockfd;
    struct sockaddr_in addr;
    struct timeval tv_out;
    char packet[PACKET_SIZE];
    struct icmp *icmp_header = (struct icmp *)packet;
    char recv_buf[PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct timeval start_time, end_time;

    // 创建原始套接字
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        return -1;
    }

    // 设置超时
    tv_out.tv_sec = timeout_ms / 1000;
    tv_out.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0) {
        close(sockfd);
        return -1;
    }

    // 解析主机名
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        struct hostent *hp = gethostbyname(host);
        if (!hp) {
            close(sockfd);
            return -1;
        }
        memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    }

    // 构造ICMP包
    memset(packet, 0, sizeof(packet));
    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_id = getpid() & 0xFFFF;
    icmp_header->icmp_seq = 1;
    icmp_header->icmp_cksum = checksum(icmp_header, ICMP_HEADER_SIZE + PACKET_SIZE - ICMP_HEADER_SIZE);

    // 记录开始时间
    gettimeofday(&start_time, NULL);

    // 发送ICMP包
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        close(sockfd);
        return -1;
    }

    // 接收响应
    if (recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &fromlen) <= 0) {
        close(sockfd);
        return -1;
    }

    // 记录结束时间
    gettimeofday(&end_time, NULL);

    close(sockfd);

    // 计算延迟(毫秒)
    long elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000 +
                   (end_time.tv_usec - start_time.tv_usec) / 1000;
    return (int)elapsed;
}

// IPv6 ping实现
int ping_ipv6(const char *host, int timeout_ms) {
    int sockfd;
    struct sockaddr_in6 addr;
    struct timeval tv_out;
    char packet[PACKET_SIZE];
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)packet;
    char recv_buf[PACKET_SIZE];
    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    struct timeval start_time, end_time;

    // 创建原始套接字
    if ((sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        return -1;
    }

    // 设置超时
    tv_out.tv_sec = timeout_ms / 1000;
    tv_out.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0) {
        close(sockfd);
        return -1;
    }

    // 解析主机名
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, host, &addr.sin6_addr) != 1) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;

        if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
            close(sockfd);
            return -1;
        }
        memcpy(&addr.sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, sizeof(addr.sin6_addr));
        freeaddrinfo(res);
    }

    // 构造ICMPv6包
    memset(packet, 0, sizeof(packet));
    icmp6_header->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_id = getpid() & 0xFFFF;
    icmp6_header->icmp6_seq = 1;
    // ICMPv6不需要校验和，内核会自动计算

    // 记录开始时间
    gettimeofday(&start_time, NULL);

    // 发送ICMPv6包
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        close(sockfd);
        return -1;
    }

    // 接收响应
    if (recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &fromlen) <= 0) {
        close(sockfd);
        return -1;
    }

    // 记录结束时间
    gettimeofday(&end_time, NULL);

    close(sockfd);

    // 计算延迟(毫秒)
    long elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000 +
                   (end_time.tv_usec - start_time.tv_usec) / 1000;
    return (int)elapsed;
}

JNIEXPORT jint JNICALL Java_yangfentuozi_hostsfeat_Ping_ping(JNIEnv *env, jobject obj, jstring host, jint timeout) {
    const char *host_str = (*env)->GetStringUTFChars(env, host, NULL);
    if (!host_str) {
        return -1;
    }

    int result = -1;

    // 检查是IPv4还是IPv6地址
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    if (inet_pton(AF_INET, host_str, &(sa.sin_addr)) == 1) {
        // IPv4地址
        result = ping_ipv4(host_str, timeout);
    } else if (inet_pton(AF_INET6, host_str, &(sa6.sin6_addr)) == 1) {
        // IPv6地址
        result = ping_ipv6(host_str, timeout);
    } else {
        // 尝试解析主机名
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host_str, NULL, &hints, &res) == 0 && res) {
            if (res->ai_family == AF_INET) {
                result = ping_ipv4(host_str, timeout);
            } else if (res->ai_family == AF_INET6) {
                result = ping_ipv6(host_str, timeout);
            }
            freeaddrinfo(res);
        }
    }

    (*env)->ReleaseStringUTFChars(env, host, host_str);
    return result;
}