import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ScanDetector implements ThreatDetector {
    private static final String SENSITIVE_PATHS = "(?i).*(\\/admin|\\/wp-login\\.php|\\/\\.env|\\/phpmyadmin|\\/config\\.yml|\\/\\.git\\/config|\\/backup\\.sql).*";
    private static final String ATTACK_TOOLS = "(?i).*(sqlmap|nikto|nmap|dirbuster|gobuster).*";
    private static final Pattern APACHE_ACCESS_LOG = Pattern.compile(
            "^(\\S+) \\S+ \\S+ \\[([^\\]]+)\\] \"\\S+ ([^\\s\"]+) [^\"]+\" (\\d{3}) \\S+ \"[^\"]*\" \"([^\"]*)\".*$");

    private final Map<String, Set<String>> ip404Urls = new HashMap<>();

    @Override
    public String execute(String logLine) {
        return analyze(java.util.Collections.singletonList(parseLogEntry(logLine)));
    }

    private LogEntry parseLogEntry(String logLine) {
        if (logLine == null || logLine.isBlank()) {
            return new LogEntry("", "", "", 0);
        }

        Matcher apacheMatcher = APACHE_ACCESS_LOG.matcher(logLine);
        if (apacheMatcher.matches()) {
            return new LogEntry(
                    apacheMatcher.group(1).trim(),
                    apacheMatcher.group(3).trim(),
                    apacheMatcher.group(5).trim(),
                    parseHttpCode(apacheMatcher.group(4).trim()));
        }

        String[] parts = logLine.split("\\|", -1);
        if (parts.length >= 4) {
            return new LogEntry(parts[0].trim(), parts[1].trim(), parts[2].trim(), parseHttpCode(parts[3].trim()));
        }

        if (parts.length >= 3) {
            return new LogEntry("", parts[0].trim(), parts[1].trim(), parseHttpCode(parts[2].trim()));
        }

        parts = logLine.split(",", -1);
        if (parts.length >= 4) {
            return new LogEntry(parts[0].trim(), parts[1].trim(), parts[2].trim(), parseHttpCode(parts[3].trim()));
        }

        if (parts.length >= 3) {
            return new LogEntry("", parts[0].trim(), parts[1].trim(), parseHttpCode(parts[2].trim()));
        }

        return new LogEntry("", logLine.trim(), "", 0);
    }

    private int parseHttpCode(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    public String analyze(List<LogEntry> logs) {
        for (LogEntry log : logs) {
            if (log.getRequestUrl().matches(SENSITIVE_PATHS)) {
                return "CRITICAL";
            }

            if (log.getUserAgent().matches(ATTACK_TOOLS)) {
                return "CRITICAL";
            }

            if (log.getHttpCode() == 404) {
                String ip = log.getIp();
                String requestUrl = log.getRequestUrl();

                if (ip != null && !ip.isBlank() && requestUrl != null && !requestUrl.isBlank()) {
                    Set<String> urls = ip404Urls.computeIfAbsent(ip, ignored -> new HashSet<>());
                    urls.add(requestUrl);

                    if (urls.size() > 20) {
                        return "HIGH";
                    }
                }
            }
        }

        return "NONE";
    }
}
