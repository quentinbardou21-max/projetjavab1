import java.time.LocalDateTime;

public class LogEntry {
    private String ip;
    private String user;
    private LocalDateTime timestamp;
    private String method;
    private String url;
    private String protocol;
    private int statusCode;
    private int responseSize;
    private String referer;
    private String userAgent;

public String getIp() {
    return ip;
}

public String getUser() {
    return user;
}

public LocalDateTime getTimestamp() {
    return timestamp;
}

public String getMethod() {
    return method;
}

public String getUrl() {
    return url;
}

public String getProtocol() {
    return protocol;
}

public int getStatusCode() {
    return statusCode;
}

public int getResponseSize() {
    return responseSize;
}

public String getReferer() {
    return referer;
}

public String getUserAgent() {
    return userAgent;
}
public LogEntry(String ip, String user, LocalDateTime timestamp, String method, String url, String protocol, int statusCode, int responseSize, String referer, String userAgent) {
    this.ip = ip;
    this.user = user;
    this.timestamp = timestamp;
    this.method = method;
    this.url = url;
    this.protocol = protocol;
    this.statusCode = statusCode;
    this.responseSize = responseSize;
    this.referer = referer;
    this.userAgent = userAgent;
}
}
