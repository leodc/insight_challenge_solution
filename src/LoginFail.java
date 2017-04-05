import java.util.Objects;

public class LoginFail {
    private int counter;
    private long timeLimit;
    private String host;

    public LoginFail(int counter, long timeLimit, String host) {
        this.counter = counter;
        this.timeLimit = timeLimit;
        this.host = host;
    }

    public int getCounter() {
        return counter;
    }

    public long getTimeLimit() {
        return timeLimit;
    }
    
    public void addToCounter(){
        counter++;
    }
    
    @Override
    public boolean equals(Object obj) {
        if(obj instanceof LoginFail){
            return ((LoginFail) obj).host.equals(host);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(host);
    }
    
}
