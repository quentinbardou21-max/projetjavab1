import java.io.IOException;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        String filePath = args.length > 0 ? args[0] : "ressources/access_log_clean.txt";
        LogParser parser = new LogParser();
        Dashboard dashboard = new Dashboard();

        try {
            List<LogEntry> entries = parser.parse(filePath);
            if (entries.isEmpty()) {
                System.out.println("Aucune entrée lue dans le fichier : " + filePath);
            } else {
                dashboard.afficher(entries);
            }
        } catch (IOException e) {
            System.err.println("Erreur lecture fichier : " + e.getMessage());
        }
    }
}
