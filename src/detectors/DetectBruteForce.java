import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class DetectBruteForce implements ThreatDetector {
    private Map<String, List<Long>> ipHistory = new HashMap<>();

    @Override
    public String execute(String logLine) {
        String[] parts = logLine.split(" ");
        if (parts.length < 9) return "";  

        String ip = parts[0];
        String code = parts[8];
        
        if (!code.equals("401") && !code.equals("403")) {
            return "";
        }

        String timePart = parts[3]; 
        long seconds = Long.parseLong(timePart.substring(timePart.length() - 2));

        if (!ipHistory.containsKey(ip)) {
            ipHistory.put(ip, new ArrayList<Long>());
        }

        List<Long> ipLogs = ipHistory.get(ip);
        ipLogs.add(seconds);

        cleanHistory(ipLogs, seconds, 300);

        return checkSeverity(ipLogs.size());
    }

    private void cleanHistory(List<Long> list, long currentTime, int seconds) {
        Iterator<Long> it = list.iterator();
        while (it.hasNext()) {
            if (currentTime - it.next() > seconds) {
                it.remove();
            } else {
                break;
            }
        }
    }

    public String checkSeverity(int attempts) {
        if (attempts > 50) return "HIGH";
        if (attempts > 10) return "MEDIUM";
        return "";
    }
}