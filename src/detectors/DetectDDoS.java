import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class DetectDDoS implements ThreatDetector {
    private double averageRps;
    private Map<String, List<Long>> ipHistory = new HashMap<>();
    private List<Long> globalHistory = new ArrayList<>();
    
    public DetectDDoS(double averageRps) {
        this.averageRps = averageRps;
    }
    
    @Override
    public String execute(String logLine) {
        String[] parts = logLine.split(" ");
        if (parts.length < 9) return "";

        String ip = parts[0]; // 172.16.1.19
        
        String timePart = parts[3]; // [15/Mar/2025:06:00:06 +0100]
        long seconds = Long.parseLong(timePart.substring(timePart.length() - 2));

        globalHistory.add(seconds);
        cleanHistory(globalHistory, seconds, 10);

        if (!ipHistory.containsKey(ip)) {
            ipHistory.put(ip, new ArrayList<Long>());
        }
        
        List<Long> ipLogs = ipHistory.get(ip);
        ipLogs.add(seconds);
        cleanHistory(ipLogs, seconds, 10);

        return checkSeverity(ipLogs.size(), globalHistory.size());
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

    public String checkSeverity(int currentIpRps, int totalGlobalRps) {
        if (totalGlobalRps > averageRps * 50 * 10) return "Alerte CRITIQUE : DDoS Distribué !";
        if (currentIpRps > averageRps * 10 * 10) return "Alerte : IP suspecte !";
        return "";
    } 
}