public class DetectBruteForce {
    public String ip;

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