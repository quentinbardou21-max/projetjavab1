import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class BlockingRuleGenerator {
    public List<String> generate(Map<String, String> severitiesByIp) {
        List<String> rules = new ArrayList<>();

        if (severitiesByIp == null) {
            return rules;
        }

        for (Map.Entry<String, String> entry : severitiesByIp.entrySet()) {
            if (shouldBlock(entry.getValue())) {
                rules.add("iptables -A INPUT -s " + entry.getKey() + " -j DROP");
            }
        }

        return rules;
    }

    public void print(Map<String, String> severitiesByIp) {
        List<String> rules = generate(severitiesByIp);
        if (rules.isEmpty()) {
            System.out.println("Aucune IP classée HIGH ou CRITICAL.");
            return;
        }

        System.out.println("=== REGLES DE BLOCAGE ===");
        for (String rule : rules) {
            System.out.println(rule);
        }
    }

    private boolean shouldBlock(String severity) {
        if (severity == null) {
            return false;
        }

        String normalized = severity.trim().toUpperCase(Locale.ROOT);
        return normalized.equals("HIGH") || normalized.equals("CRITICAL");
    }
}
