public class ThreatLogEntry {
    private final String ip;
    private final String requestUrl;
    private final String userAgent;
    private final int httpCode;

    public ThreatLogEntry(String ip, String requestUrl, String userAgent, int httpCode) {
        this.ip = ip;
        this.requestUrl = requestUrl;
        this.userAgent = userAgent;
        this.httpCode = httpCode;
    }

    public ThreatLogEntry(String requestUrl, String userAgent, int httpCode) {
        this("", requestUrl, userAgent, httpCode);
    }

    public ThreatLogEntry(String requestUrl) {
        this(requestUrl, "", 0);
    }

    public String getIp() {
        return ip;
    }

    public String getRequestUrl() {
        return requestUrl;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public int getHttpCode() {
        return httpCode;
    }
}