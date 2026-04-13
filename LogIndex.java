import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;

public class LogIndex {
    private HashMap<String, List<LogEntry>> indexParIp = new HashMap<>();
    private TreeMap<LocalDateTime, List<LogEntry>> indexParDate = new TreeMap<>();
    
public void indexer(List<LogEntry> entries) {
    for (LogEntry entry : entries) {
       indexParIp.computeIfAbsent(entry.getIp(), k -> new ArrayList<>()).add(entry);
       indexParDate.computeIfAbsent(entry.getTimestamp(), k -> new ArrayList<>()).add(entry);
    }
}
public HashMap<String, List<LogEntry>>getIndexParIp() {
    return indexParIp;
}

public TreeMap<LocalDateTime, List<LogEntry>>getIndexParDate() {
    return indexParDate;
}
}