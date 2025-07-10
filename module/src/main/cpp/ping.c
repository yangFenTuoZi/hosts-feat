#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#define PACKET_SIZE 64

// ICMP包头校验和计算
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
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

// 执行ping操作
int do_ping(const char *host, int timeout_ms) {
    struct sockaddr_in addr;
    struct hostent *h;
    struct icmp icmp_pkt;
    struct timeval tv_out, tv_start, tv_end;
    int sockfd, ret, len;
    char packet[PACKET_SIZE];
    fd_set readfds;

    // 解析主机名
    if ((h = gethostbyname(host)) == NULL) {
        return -1;
    }

    // 设置目标地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = h->h_addrtype;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = *(unsigned long *)h->h_addr;

    // 创建原始套接字
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        return -1;
    }

    // 设置超时
    tv_out.tv_sec = timeout_ms / 1000;
    tv_out.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out))) {
        close(sockfd);
        return -1;
    }

    // 构造ICMP包
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    icmp_pkt.icmp_type = ICMP_ECHO;
    icmp_pkt.icmp_code = 0;
    icmp_pkt.icmp_id = getpid() & 0xFFFF;
    icmp_pkt.icmp_seq = 1;
    icmp_pkt.icmp_cksum = checksum(&icmp_pkt, sizeof(icmp_pkt));

    // 记录开始时间
    gettimeofday(&tv_start, NULL);

    // 发送ICMP包
    if (sendto(sockfd, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        close(sockfd);
        return -1;
    }

    // 等待响应
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    ret = select(sockfd + 1, &readfds, NULL, NULL, &tv_out);

    if (ret <= 0) {
        close(sockfd);
        return -1; // 超时或错误
    }

    // 接收响应
    len = recvfrom(sockfd, packet, sizeof(packet), 0, NULL, NULL);
    if (len < 0) {
        close(sockfd);
        return -1;
    }

    // 记录结束时间
    gettimeofday(&tv_end, NULL);

    close(sockfd);

    // 计算延迟(毫秒)
    long elapsed = (tv_end.tv_sec - tv_start.tv_sec) * 1000 +
                   (tv_end.tv_usec - tv_start.tv_usec) / 1000;

    return (int)elapsed;
}

// JNI方法实现
JNIEXPORT jint JNICALL Java_yangfentuozi_hostsfeat_Ping_ping(JNIEnv *env, jobject obj, jstring host, jint timeout) {
    const char *host_str = (*env)->GetStringUTFChars(env, host, 0);
    int result = do_ping(host_str, timeout);
    (*env)->ReleaseStringUTFChars(env, host, host_str);
    return result;
}
