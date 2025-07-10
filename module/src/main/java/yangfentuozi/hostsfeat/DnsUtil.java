package yangfentuozi.hostsfeat;

import static yangfentuozi.hostsfeat.Global.IPV6;
import static yangfentuozi.hostsfeat.Global.TIMEOUT;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class DnsUtil {
    // DNS查询类型 - A记录
    private static final int DNS_QUERY_TYPE_A = 1;
    // DNS查询类型 - AAAA记录
    private static final int DNS_QUERY_TYPE_AAAA = 28;
    // DNS查询类 - IN (Internet)
    private static final int DNS_QUERY_CLASS_IN = 1;
    // DNS端口
    private static final int DNS_PORT = 53;

    public static List<String> queryDns(String domain, String dnsServer) throws IOException {
        if (IPV6) {
            // 查询AAAA记录
            List<String> ipv6List = queryDnsByType(domain, dnsServer, DNS_QUERY_TYPE_AAAA);
            // 查询A记录
            List<String> ipv4List = queryDnsByType(domain, dnsServer, DNS_QUERY_TYPE_A);
            // 合并，IPv6优先
            List<String> result = new ArrayList<>();
            result.addAll(ipv6List);
            result.addAll(ipv4List);
            return result;
        } else {
            // 只查A记录
            return queryDnsByType(domain, dnsServer, DNS_QUERY_TYPE_A);
        }
    }

    private static List<String> queryDnsByType(String domain, String dnsServer, int queryType) throws IOException {
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
        dos.writeShort(queryType);  // 查询类型: A记录或AAAA记录
        dos.writeShort(DNS_QUERY_CLASS_IN); // 查询类: IN

        byte[] dnsQuery = baos.toByteArray();

        // 发送DNS查询
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(TIMEOUT);

        InetAddress dnsAddress = InetAddress.getByName(dnsServer);
        DatagramPacket packet = new DatagramPacket(dnsQuery, dnsQuery.length, dnsAddress, DNS_PORT);
        socket.send(packet);

        // 接收响应
        byte[] response = new byte[1024];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        socket.receive(responsePacket);
        socket.close();

        // 解析响应
        return parseDnsResponse(responsePacket.getData());
    }

    private static List<String> parseDnsResponse(byte[] response) throws IOException {
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

            if ((type == DNS_QUERY_TYPE_A || type == DNS_QUERY_TYPE_AAAA) && (dataLength == 4 || dataLength == 16)) {
                byte[] ipBytes = new byte[dataLength];
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
