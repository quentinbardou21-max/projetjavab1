public class LogEntry {
    private final String ip;
    private final String requestUrl;
    private final String userAgent;
    private final int httpCode;

    public LogEntry(String ip, String requestUrl, String userAgent, int httpCode) {
        this.ip = ip;
        this.requestUrl = requestUrl;
        this.userAgent = userAgent;
        this.httpCode = httpCode;
    }

    public LogEntry(String requestUrl, String userAgent, int httpCode) {
        this("", requestUrl, userAgent, httpCode);
    }

    public LogEntry(String requestUrl) {
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