import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class WhitelistManager {
    private final Set<String> whitelist = new HashSet<>();

    public void load(String filePath) throws IOException {
        whitelist.clear();

        List<String> lines = Files.readAllLines(Path.of(filePath));
        for (String line : lines) {
            String ip = normalize(line);
            if (ip.isEmpty() || ip.startsWith("#")) {
                continue;
            }
            whitelist.add(ip);
        }
    }

    public boolean isWhitelisted(String ip) {
        return whitelist.contains(normalize(ip));
    }

    public Map<String, String> suppressWhitelistedAlerts(Map<String, String> severitiesByIp) {
        Map<String, String> filtered = new HashMap<>();

        if (severitiesByIp == null) {
            return filtered;
        }

        for (Map.Entry<String, String> entry : severitiesByIp.entrySet()) {
            if (!isWhitelisted(entry.getKey())) {
                filtered.put(entry.getKey(), entry.getValue());
            }
        }

        return filtered;
    }

    public Set<String> getWhitelist() {
        return new HashSet<>(whitelist);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
