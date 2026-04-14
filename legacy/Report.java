import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Report {

    public static void main(String[] args) throws Exception {
        DetectBruteForce bruteForceDetector = new DetectBruteForce();
        
        int highAlertCount = 0;
        int mediumAlertCount = 0;
        List<String> eventTimeline = new ArrayList<>();
        Map<String, List<String>> detailsByIp = new HashMap<>();

        String[] logFiles = {"ressources/access_log_clean.txt", "ressources/access_log_attack.txt"};

        for (String fileName : logFiles) {
            System.out.println("Analyse en cours : " + fileName);
            
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            String line;

            while ((line = reader.readLine()) != null) {
                String alertLevel = bruteForceDetector.execute(line);

                if (!alertLevel.isEmpty()) {
                    String ipAddress = line.split(" ")[0]; 
                    String fullAlertMessage = "[" + alertLevel + "] (" + fileName + ") IP: " + ipAddress + " - " + line; 

                    eventTimeline.add(fullAlertMessage);

                    if (alertLevel.equals("HIGH")) highAlertCount++;
                    if (alertLevel.equals("MEDIUM")) mediumAlertCount++;

                    if (!detailsByIp.containsKey(ipAddress)) {
                        detailsByIp.put(ipAddress, new ArrayList<>());
                    }
                    detailsByIp.get(ipAddress).add(fullAlertMessage);
                }
            }
            reader.close();
        }

        PrintWriter writer = new PrintWriter("rapport_securite.txt"); 

        writer.println("=== 6. RÉSUMÉ EXÉCUTIF ===");
        writer.println("Nombres d'alertes : " + highAlertCount + "(HIGH)");
        writer.println("Nombres d'alertes: " + mediumAlertCount + "(MEDIUM)");
        writer.println();

        writer.println("=== 7. TIMELINE DES INCIDENTS ===");
        for (String event : eventTimeline) {
            writer.println(event);
        }
        writer.println();

        writer.println("=== 8. DÉTAILS PAR IP SUSPECTE ===");
        for (String ip : detailsByIp.keySet()) {
            writer.println("IP: " + ip + " (" + detailsByIp.get(ip).size() + " alerts)");
            for (String detail : detailsByIp.get(ip)) {
                writer.println("   -> " + detail);
            }
        }
        writer.println();

        writer.println("=== 9. RECOMMANDATIONS ===");
        writer.println("- Brute-Force : Bannir automatiquement les IPs via le Pare-feu après plusieurs tentatives.");
        writer.println("- DDoS : Activer la protection Cloud ou limiter le taux de requêtes.");
        writer.println("- Injection SQL : Filtrer les caractères spéciaux (', ;, --) et utiliser des requêtes préparées.");
        writer.println("- Scan de vulnérabilités : Bloquer les IPs utilisant des outils de scan (nikto, sqlmap, nmap...).");

        writer.close();
        System.out.println("Analyse terminée. Rapport généré avec succès.");
    }
}
