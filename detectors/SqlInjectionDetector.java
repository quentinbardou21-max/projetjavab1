import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class SqlInjectionDetector implements ThreatDetector {

    private static final String SQL_REGEX = "(?i).*('|%27|\"|%22|--|%2D%2D|\\bUNION\\b|\\bSELECT\\b|\\bDROP\\b|\\bOR\\b\\s+1=1).*";
    private static final Pattern PATTERN = Pattern.compile(SQL_REGEX);

    @Override
    public String execute(String logLine) {
        return analyze(java.util.Collections.singletonList(new ThreatLogEntry(extractRequestUrl(logLine))));
    }

    private String extractRequestUrl(String logLine) {
        if (logLine == null) {
            return "";
        }

        String[] parts = logLine.split("\\|", -1);
        if (parts.length > 0 && !parts[0].isBlank()) {
            return parts[0].trim();
        }

        parts = logLine.split(",", -1);
        if (parts.length > 0 && !parts[0].isBlank()) {
            return parts[0].trim();
        }

        return logLine.trim();
    }

    public String analyze(List<ThreatLogEntry> logs) {
        for (ThreatLogEntry log : logs) {
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
