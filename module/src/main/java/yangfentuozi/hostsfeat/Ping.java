package yangfentuozi.hostsfeat;

public class Ping {
    static {
        System.loadLibrary("ping");
    }
    public static int ping(String host) {
        return ping(host, Global.TIMEOUT);
    }
    public static native int ping(String host, int timeoutMs);
}