import java.time.LocalDateTime;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParser {
    private static final String PATTERN = "^(\\S+) \\S+ (\\S+) \\[(.+?)\\] \"(\\S+) (\\S+) (\\S+)\" (\\d{3}) (\\d+|-) \"(.*?)\" \"(.*?)\"$";
    public List<LogEntry> parse(String cheminFichier) throws IOException {
    List<LogEntry> entries = new ArrayList<>();
    List<String> lines = Files.readAllLines(Paths.get(cheminFichier));

    Pattern pattern = Pattern.compile(PATTERN);
    for (String line : lines) {
        Matcher m = pattern.matcher(line);
        if (m.matches()) {
            String ip = m.group(1);
            String user = m.group(2);
            LocalDateTime timestamp = LocalDateTime.parse(m.group(3), DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH));
            String method = m.group(4);
            String url = m.group(5);
            String protocol = m.group(6);
            int statusCode = Integer.parseInt(m.group(7));
            int responseSize = m.group(8).equals("-") ? 0 : Integer.parseInt(m.group(8));
            String referer = m.group(9);
            String userAgent = m.group(10);

            entries.add(new LogEntry(ip, user, timestamp, method, url, protocol, statusCode, responseSize, referer, userAgent));
        }
    }
    return entries;
}
}