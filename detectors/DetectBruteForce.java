public class DetectBruteForce implements ThreatDetector {
    private int attempts = 0; 

    public String execute(String logLine) {
        return checkSeverity(attempts);
    }

    public String Threshold (int answersPerIp) {
        if (answersPerIp > 10) {
            return "danger";
        } else {
            return "";
        }
    }

    public String checkSeverity(int attempts) {
        if (attempts > 50) {
            return "HIGH";
        } else if (attempts > 10) {
            return "MEDIUM";
        } else {
            return "";
        }
    }
}