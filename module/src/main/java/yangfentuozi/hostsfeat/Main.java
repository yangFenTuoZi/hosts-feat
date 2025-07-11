package yangfentuozi.hostsfeat;

import static yangfentuozi.hostsfeat.Global.IPV6;
import static yangfentuozi.hostsfeat.Global.TIMEOUT;
import static yangfentuozi.hostsfeat.Ping.ping;

import android.system.Os;
import android.system.OsConstants;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        boolean help = false;
        File originHosts = null, outputHosts = null, dnsConfig = null;
        List<File> domainConfigs = new ArrayList<>();
        List<String> dnsServers = new ArrayList<>(), domains = new ArrayList<>();
        for (String arg : args) {
            if (Objects.equals(arg, "--help")) {
                help = true;
                break;
            } else if (arg.startsWith("--origin=")) {
                originHosts = new File(arg.substring(9));
                if (!originHosts.exists()) {
                    System.err.printf("Error: origin hosts file: '%s' doesn't exist!\n", originHosts.getPath());
                    System.exit(1);
                }
                if (originHosts.isDirectory()) {
                    System.err.printf("Error: origin hosts file: '%s' cannot be a directory!\n", originHosts.getPath());
                    System.exit(1);
                }
            } else if (arg.startsWith("--output=")) {
                outputHosts = new File(arg.substring(9));
            } else if (arg.startsWith("--domain=")) {
                if (arg.contains(":")) {
                    for (String config : arg.substring(9).split(":")) {
                        File configFile = new File(config);
                        if (configFile.exists() && configFile.isFile())
                            domainConfigs.add(configFile);
                    }
                } else {
                    File config = new File(arg.substring(9));
                    if (!config.exists()) {
                        System.err.printf("Error: domain config file/dir: '%s' doesn't exist!\n", config.getPath());
                        System.exit(1);
                    }
                    if (config.isFile())
                        domainConfigs.add(config);
                    else {
                        File[] configs = config.listFiles((file, s) -> file.isFile() && s.endsWith(".txt"));
                        if (configs != null) {
                            for (File configFile : configs) {
                                if (configFile.exists() && configFile.isFile())
                                    domainConfigs.add(configFile);
                            }
                        }
                    }
                }
            } else if (arg.startsWith("--dns=")) {
                dnsConfig = new File(arg.substring(6));
                if (!dnsConfig.exists()) {
                    System.err.printf("Error: dns config file: '%s' doesn't exist!\n", dnsConfig.getPath());
                    System.exit(1);
                }
                if (dnsConfig.isDirectory()) {
                    System.err.printf("Error: dns config file: '%s' cannot be a directory!\n", dnsConfig.getPath());
                    System.exit(1);
                }
            } else if (arg.startsWith("--timeout=")) {
                TIMEOUT = Integer.parseInt(arg.substring(10));
            } else if (arg.equals("--ipv6")) {
                IPV6 = true;
            }
        }
        if (help || outputHosts == null || dnsConfig == null || domainConfigs.isEmpty()) {
            System.err.print("""
                    Usage: this [--origin=] --output= --domain= --dns= [--timeout=] [--ipv6]
                    Description:
                        --origin:   原 hosts 文件，要求可读
                        --output:   将输出的处理好的 hosts 文件，如已存在，将覆写
                        --domain:   待处理域名列表，可以是一个文件夹、一个或多个 txt 文件。
                                    单个文件请用 ':' 隔开
                                    作文件夹时将读取其后缀为 .txt 的所有子文件作为配置文件
                        --dns:      DNS 服务器列表，只能为一个 txt 文件
                        --timeout:  超时时间，单位毫秒，默认为 3000
                        --ipv6:     有该选项时将查询 IPv6 地址
                    
                        配置文件中的 DNS 服务器/待处理域名 均使用 ',' 隔开，多行不必额外使用 ','
                    """);
            System.exit(1);
        }

        try {
            BufferedReader br = new BufferedReader(new FileReader(dnsConfig));
            String inline;
            while ((inline = br.readLine()) != null) {
                dnsServers.addAll(List.of(inline.split(",")));
            }
            br.close();
        } catch (IOException e) {
            System.err.println("Error while reading dns config file");
            throw new RuntimeException(e);
        }

        for (File domainConfig : domainConfigs) {
            try {
                BufferedReader br = new BufferedReader(new FileReader(domainConfig));
                String inline;
                while ((inline = br.readLine()) != null) {
                    domains.addAll(List.of(inline.split(",")));
                }
                br.close();
            } catch (IOException e) {
                System.err.println("Error while reading dns config file: " + domainConfig.getPath());
                e.printStackTrace(System.err);
            }
        }

        FileWriter fw;
        if (originHosts == null) {
            try {
                fw = new FileWriter(outputHosts);
            } catch (IOException e) {
                System.err.println("Error while writing output hosts file");
                throw new RuntimeException(e);
            }
        } else {
            boolean append = true;

            try {
                FileInputStream fis = new FileInputStream(originHosts);
                FileOutputStream fos = new FileOutputStream(outputHosts);
                transferTo(fis, fos);
                fis.close();
                fos.close();
            } catch (IOException e) {
                System.err.println("Error while copying origin hosts file to output hosts file");
                e.printStackTrace(System.err);
                append = false;
            }

            try {
                fw = new FileWriter(outputHosts, append);
                if (append) {
                    fw.write("\n");
                }
            } catch (IOException e) {
                System.err.println("Error while writing output hosts file");
                throw new RuntimeException(e);
            }
        }

        dnsServers = filterReachableDnsServers(dnsServers);

        for (String domain : domains) {
            String ip = findBestIp(domain, dnsServers);
            if (ip == null) {
                System.err.println("None available ip: " + domain);
                ip = "#";
            }
            try {
                fw.write(String.format("%-20s%s\n", ip, domain));
            } catch (Exception e) {
                System.err.println("Error while writing output hosts file");
                throw new RuntimeException(e);
            }
        }
        try {
            fw.close();
        } catch (IOException e) {
            System.err.println("Error while closing output hosts file");
            throw new RuntimeException(e);
        }

        System.out.println("Complete.");
        System.exit(0);
    }

    // From DeepSeek V3
    public static String findBestIp(String domain, List<String> dnsServers) {
        Set<String> allIps = resolveDomainFromAllDnsServers(domain, dnsServers);
        if (allIps.isEmpty()) {
            return null;
        }
        System.out.println(domain + " -> " + Arrays.toString(allIps.toArray()));
        Map<String, Integer> ipPingResults = pingAllIps(allIps);
        if (ipPingResults.isEmpty()) return null;
        return Collections.min(ipPingResults.entrySet(), Map.Entry.comparingByValue()).getKey();
    }

    private static Set<String> resolveDomainFromAllDnsServers(String domain, List<String> dnsServers) {
        Set<String> ips = new HashSet<>();

        for (String dnsServer : dnsServers) {
            try {
                // 使用自定义DNS查询方法
                List<String> resolvedIps = NSLookup.lookup(domain, dnsServer);
                ips.addAll(resolvedIps);
            } catch (Exception e) {
                System.err.println("DNS query failed for server " + dnsServer + ": " + e.getMessage());
            }
        }

        return ips;
    }

    private static Map<String, Integer> pingAllIps(Set<String> ips) {
        Map<String, Integer> results = new HashMap<>();

        for (String ip : ips) {
            try {
                int pingTime = ping(ip);

                if (pingTime != -1) {
                    results.put(ip, pingTime);
                    System.out.println("Ping " + ip + " - " + pingTime + "ms");
                } else {
                    System.err.println("Ping failed for " + ip + ": Host not reachable");
                }
            } catch (Exception e) {
                System.err.println("Ping failed for " + ip + ": " + e.getMessage());
            }
        }

        return results;
    }

    public static List<String> filterReachableDnsServers(List<String> dnsServers) {
        List<String> reachableServers = new ArrayList<>();

        for (String server : dnsServers)
            if (isReachable(server))
                reachableServers.add(server);

        return reachableServers;
    }

    private static boolean isReachable(String host) {
        return ping(host) != -1;
    }

    public static int BUFFER_SIZE = (int) Os.sysconf(OsConstants._SC_PAGESIZE);

    public static void transferTo(InputStream in, OutputStream out) throws IOException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer, 0, BUFFER_SIZE)) >= 0) {
            out.write(buffer, 0, read);
        }
    }
}
