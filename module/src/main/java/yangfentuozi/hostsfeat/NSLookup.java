package yangfentuozi.hostsfeat;

import java.util.Arrays;
import java.util.List;

public class NSLookup {
    static {
        System.loadLibrary("nslookup");
    }
    public static List<String> lookup(String domain, String dns) {
        return Arrays.asList(lookup(domain, dns, Global.TIMEOUT));
    }
    public static native String[] lookup(String domain, String dns, int timeout);
}