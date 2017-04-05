import java.time.Instant;
import java.util.Objects;

public class Counter {
    private final String label;
    private Integer counter;
    private long timeLimit;
    private long startTime;

    private Instant instant;

    public void setInstant(Instant instant) {
        this.instant = instant;
    }

    public Instant getInstant() {
        return instant;
    }

    public Counter(String label, int counter, long startTime) {
        this.label = label;
        this.counter = counter;
        this.startTime = startTime;
        this.timeLimit = startTime + (60 * 60 * 1000); // 60 minutes -> ms
    }

    public Counter(String label, Integer counter) {
        this.label = label;
        this.counter = counter;
    }

    public void setTimeLimit(long timeLimit) {
        this.timeLimit = timeLimit;
    }

    public long getTimeLimit() {
        return timeLimit;
    }

    public Integer getCounter() {
        return counter;
    }

    public long getStartTime() {
        return startTime;
    }

    public String getLabel() {
        return label;
    }

    public void addToCounter() {
        counter++;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Counter) {
            return ((Counter) obj).label.equals(label);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(label);
    }

}
