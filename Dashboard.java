public class Dashboard {
    public void afficher(List<LogEntry> entries) {
        System.out.println("========== DASHBOARD ==========");
        System.out.println("Total requêtes : " + entries.size());
        System.out.println("================================");
        HashMap<String, Integer> compteurIp = new HashMap<>();
        for (LogEntry entry : entries) {
            compteurIp.merge(entry.getIp(), 1, Integer::sum);
        }
        System.out.println("=== TOP 10 IPS ===");
        compteurIp.entrySet()
        .stream()
        .sorted((a, b) -> b.getValue() - a.getValue())
        .limit(10)
        .forEach(e -> System.out.println(e.getKey() + " : " + e.getValue())
        );
        
        HashMap<String, Integer> compteurUrl = new HashMap<>();
        for (LogEntry entry : entries) {
            compteurUrl.merge(entry.getUrl(), 1, Integer::sum);
        }
        System.out.println("=== TOP 10 URLs ===");
        compteurUrl.entrySet()
        .stream()
        .sorted((a, b) -> b.getValue() - a.getValue())
        .limit(10)
        .forEach(e -> System.out.println(e.getKey() + " : " + e.getValue())
        );

        HashMap<String, Integer> compteurUserAgent = new HashMap<>();
        for (LogEntry entry : entries) {
            compteurUserAgent.merge(entry.getUserAgent(), 1, Integer::sum);
        }
        System.out.println("=== TOP 5 Users-agents ===");
        compteurUserAgent.entrySet()
        .stream()
        .sorted((a, b) -> b.getValue() - a.getValue())
        .limit(5)
        .forEach(e -> System.out.println(e.getKey() + " : " + e.getValue())
        );

        HashMap<String, Integer> compteurStatusCode = new HashMap<>();
        for (LogEntry entry : entries) {
            compteurStatusCode.merge(String.valueOf(entry.getStatusCode()), 1, Integer::sum);
        }
        System.out.println("=== Codes HTTP ===");
        compteurStatusCode.entrySet()
        .stream()
        .sorted((a, b) -> b.getValue() - a.getValue())
        .forEach(e -> System.out.println(e.getKey() + " : " + e.getValue())
        );
    }
}