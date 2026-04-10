import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

class LogEntry {
    private String requestUrl;

    public LogEntry(String requestUrl) {
        this.requestUrl = requestUrl;
    }

    public String getRequestUrl() {
        return requestUrl;
    }
}

class SqlInjectionDetector {

    private static final String SQL_REGEX = "(?i).*('|%27|\"|%22|--|%2D%2D|\\bUNION\\b|\\bSELECT\\b|\\bDROP\\b|\\bOR\\b\\s+1=1).*";
    private static final Pattern PATTERN = Pattern.compile(SQL_REGEX);

    public String analyze(List<LogEntry> logs) {
        for (LogEntry log : logs) {
            String url = log.getRequestUrl();
            
            if (url != null) {
                Matcher matcher = PATTERN.matcher(url);
                if (matcher.matches()) {
                    return "HIGH";
                }
            }
        }
        return "NONE";
    }
}
