package com.jb.thickclient;

/** Build a selective PAC file that only proxies hosts matching a regex. */
public class PacBuilder {
    public static String buildSelectivePac(String burpHost, int burpPort, String hostRegex) {
        String jsSafe = toJsRegex(hostRegex);
        return "function FindProxyForURL(url, host) {\n" +
               "  var re = new RegExp(" + jsSafe + ");\n" +
               "  if (re.test(host)) { return \"PROXY " + burpHost + ":" + burpPort + "; DIRECT\"; }\n" +
               "  return \"DIRECT\";\n" +
               "}\n";
    }
    private static String toJsRegex(String rx) {
        String s = rx.replace("\\", "\\\\").replace("\"", "\\\"");
        return '\"' + s + '\"';
    }
}
