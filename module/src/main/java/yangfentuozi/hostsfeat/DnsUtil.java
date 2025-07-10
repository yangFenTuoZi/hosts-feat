package yangfentuozi.hostsfeat;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DnsUtil {
    // DNS查询类型 - A记录
    private static final int DNS_QUERY_TYPE_A = 1;
    // DNS查询类 - IN (Internet)
    private static final int DNS_QUERY_CLASS_IN = 1;
    // DNS端口
    private static final int DNS_PORT = 53;
    // 超时时间(毫秒)
    private static final int DNS_TIMEOUT = 2000;

    public static List<String> queryDns(String domain, String dnsServer) throws IOException {
        // 生成随机ID
        short id = (short) new Random().nextInt(32767);

        // 创建DNS查询报文
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // DNS报文头部
        dos.writeShort(id);          // ID
        dos.writeShort(0x0100);      // Flags: Standard query
        dos.writeShort(1);           // Questions: 1
        dos.writeShort(0);           // Answer RRs: 0
        dos.writeShort(0);           // Authority RRs: 0
        dos.writeShort(0);           // Additional RRs: 0

        // 写入查询问题部分
        String[] domainParts = domain.split("\\.");
        for (String part : domainParts) {
            dos.writeByte(part.length());
            dos.write(part.getBytes());
        }
        dos.writeByte(0);            // 结束域名部分
        dos.writeShort(DNS_QUERY_TYPE_A);  // 查询类型: A记录
        dos.writeShort(DNS_QUERY_CLASS_IN); // 查询类: IN

        byte[] dnsQuery = baos.toByteArray();

        // 发送DNS查询
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(DNS_TIMEOUT);

        InetAddress dnsAddress = InetAddress.getByName(dnsServer);
        DatagramPacket packet = new DatagramPacket(dnsQuery, dnsQuery.length, dnsAddress, DNS_PORT);
        socket.send(packet);

        // 接收响应
        byte[] response = new byte[1024];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        socket.receive(responsePacket);
        socket.close();

        // 解析响应
        return parseDnsResponse(responsePacket.getData(), domain);
    }

    private static List<String> parseDnsResponse(byte[] response, String domain) throws IOException {
        List<String> ips = new ArrayList<>();
        ByteBuffer buffer = ByteBuffer.wrap(response);

        // 跳过头部
        buffer.position(12);

        // 跳过问题部分
        while (true) {
            int len = buffer.get() & 0xFF;
            if (len == 0) break;
            buffer.position(buffer.position() + len);
        }
        buffer.position(buffer.position() + 4); // 跳过类型和类

        // 读取回答部分
        int answerCount = (response[6] & 0xFF) << 8 | (response[7] & 0xFF);
        for (int i = 0; i < answerCount; i++) {
            // 跳过可能的域名指针
            if ((buffer.get(buffer.position()) & 0xC0) == 0xC0) {
                buffer.position(buffer.position() + 2);
            } else {
                // 如果不是指针，跳过域名
                while (buffer.get() != 0);
            }

            int type = buffer.getShort() & 0xFFFF;
            buffer.getShort(); // 跳过类
            buffer.getInt();   // 跳过TTL
            int dataLength = buffer.getShort() & 0xFFFF;

            if (type == DNS_QUERY_TYPE_A && dataLength == 4) {
                // A记录且数据长度为4字节(IPv4地址)
                byte[] ipBytes = new byte[4];
                buffer.get(ipBytes);
                ips.add(InetAddress.getByAddress(ipBytes).getHostAddress());
            } else {
                // 跳过其他类型的记录
                buffer.position(buffer.position() + dataLength);
            }
        }

        return ips;
    }
}
