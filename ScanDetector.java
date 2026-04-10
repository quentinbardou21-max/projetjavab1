import java.util.List;

class LogEntry {
    private String requestUrl;
    private String userAgent; 
    private int httpCode;    

    public LogEntry(String requestUrl, String userAgent, int httpCode) {
        this.requestUrl = requestUrl;
        this.userAgent = userAgent;
        this.httpCode = httpCode;
    }

    public String getRequestUrl() { return requestUrl; }
    public String getUserAgent() { return userAgent; }
    public int getHttpCode() { return httpCode; }
}

class ScanDetector {    
    private static final String SENSITIVE_PATHS = "(?i).*(\\/admin|\\/wp-login\\.php|\\/\\.env|\\/phpmyadmin|\\/config\\.yml|\\/\\.git\\/config|\\/backup\\.sql).*";
    private static final String ATTACK_TOOLS = "(?i).*(sqlmap|nikto|nmap|dirbuster|gobuster).*";

    public String analyze(List<LogEntry> logs) {
        int count404 = 0;

        for (LogEntry log : logs) {
            if (log.getRequestUrl().matches(SENSITIVE_PATHS)) {
                return "CRITICAL";
            }

            if (log.getUserAgent().matches(ATTACK_TOOLS)) {
                return "CRITICAL";
            }

            if (log.getHttpCode() == 404) {
                count404++;
            }
        }
        
        if (count404 > 20) {
            return "HIGH";
        }

        return "NONE";
    }
}
