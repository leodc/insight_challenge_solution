import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Leo
 */
public class LogAnalyzer {

    // class properties
    private boolean skipRootResource;
    private boolean multipleInput;
    private String filename;

    private int maxLoginAttempts = 3;
    private int loginJailTime = 300000; // ms
    private int loginAttemptsWindowTime = 20000;

    private String dateFormat = "dd/MMM/yyyy:HH:mm:ss Z";

    // feature 1
    private HashMap<String, Integer> hostCounter = new HashMap<>();

    // feature 2
    private HashMap<String, Double> resourceBandwith = new HashMap<>();

    // feature 3
    private SortedSet<Counter> timeWindows = new TreeSet<>((Counter o1, Counter o2) -> {
        int res = o2.getCounter().compareTo(o1.getCounter());
        return res != 0 ? res : o1.getLabel().compareTo(o2.getLabel());
    });

    // feature 4
    private HashMap<String, LoginFail> failedLogins = new HashMap<>();
    private HashMap<String, Long> bloquedHosts = new HashMap<>();
    private ArrayList<String> blocked = new ArrayList<>();

    public LogAnalyzer(boolean skipRootResource) {
        this(skipRootResource, false);
    }

    public LogAnalyzer(boolean skipRootResource, boolean multipleInput) {
        this.skipRootResource = skipRootResource;
        this.multipleInput = multipleInput;
    }

    public void process(String fileName) {
        this.filename = fileName;

        try {
            System.out.println("Processing \"" + fileName + "\"...");

            FileInputStream fstream = new FileInputStream(fileName);
            DataInputStream in = new DataInputStream(fstream);
            BufferedReader br = new BufferedReader(new InputStreamReader(in));

            String record, bytes, resource, host, timestamp = "";
            boolean firstRun = true;
            long recordTime;
            Counter counter;
            Date recordDate, counterDate;
            ZoneOffset zoneOffset;

            DateFormat df = new SimpleDateFormat(dateFormat);
            
            List<Counter> timeWindowCounterList = new ArrayList<>();

            Pattern patterLog = Pattern.compile("(?<host>.*) - - \\[(?<timestamp>.*)\\] \"(?<request>.*)\" (?<response>\\d+) (?<bytes>\\d+)");
            Matcher m;
            while ((record = br.readLine()) != null) {
                m = patterLog.matcher(record);

                if (m.find()) {
                    resource = m.group("request").split(" ")[1];

                    if (skipRootResource && resource.equals("/")) {
                        continue;
                    }

                    host = m.group("host");
                    bytes = m.group("bytes");
                    timestamp = m.group("timestamp");

                    zoneOffset = ZoneOffset.of(timestamp.split(" ")[1]);
                    
                    df.setTimeZone(TimeZone.getTimeZone(zoneOffset));

                    recordDate = df.parse(timestamp);
                    recordTime = recordDate.getTime();

                    if (firstRun) {
                        timeWindowCounterList.add(new Counter(timestamp, 0, recordTime));
                        firstRun = false;
                    }

                    // Feature 1
                    addToFeature1(host);

                    // Feature 2
                    addToFeature2(bytes, resource);

                    // Feature 3
                    // create the counters between the last time refference and the recordTime
                    long jump_ms = 1000, time;
                    counter = timeWindowCounterList.get(timeWindowCounterList.size() - 1);
                    while (counter.getStartTime() + jump_ms <= recordTime) {
                        counterDate = df.parse(counter.getLabel());
                        time = counterDate.getTime() + jump_ms;
                        counterDate.setTime(time);
                        
                        counter = new Counter(df.format(counterDate), 0, time);
                        if (recordTime <= counter.getTimeLimit()) {
                            timeWindowCounterList.add(counter);
                        }
                    }

                    // update the valid counters and remove the completed ones
                    for (int i = 0; i < timeWindowCounterList.size(); i++) {
                        counter = timeWindowCounterList.get(i);
                        if (recordTime <= counter.getTimeLimit()) {
                            counter.addToCounter();
                        } else {
                            addToFeature3(counter.getLabel(), counter.getCounter());
                            timeWindowCounterList.remove(i);
                            i--;
                        }
                    }

                    // Feature 4
                    addToFeature4(host, recordTime, record, resource, m.group("response"));
                }
            }
            in.close();

            for (int i = 0; i < timeWindowCounterList.size(); i++) {
                counter = timeWindowCounterList.get(i);
                addToFeature3(counter.getLabel(), counter.getCounter());
            }

            printResults();
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        } catch (ParseException ex) {
            Logger.getLogger(LogAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void printResults() throws FileNotFoundException {
        final int elementsToPrint = 10;

        if (multipleInput) {
            // one directory for each input file
            String[] split = filename.split("/");
            filename = split[split.length - 1];
            new File("log_output/" + filename).mkdirs();
        }

        Thread hostWriter = new Thread(() -> {
            String outputFile = multipleInput ? "log_output/" + filename + "/hosts.txt" : "log_output/hosts.txt";

            try (PrintWriter pw = new PrintWriter(outputFile)) {
                int i = 0;
                Comparator<Map.Entry<String, Integer>> comparatorHostCounter = (Map.Entry<String, Integer> o1, Map.Entry<String, Integer> o2) -> {
                    int res = o2.getValue().compareTo(o1.getValue());
                    return res != 0 ? res : o1.getKey().compareTo(o2.getKey());
                };

                // sort
                List<Map.Entry<String, Integer>> list = new LinkedList<>(hostCounter.entrySet());
                list.sort(comparatorHostCounter);

                Iterator<Map.Entry<String, Integer>> iterator = list.iterator();
                while (iterator.hasNext() && elementsToPrint > i++) {
                    Map.Entry<String, Integer> next = iterator.next();
                    pw.append(next.getKey())
                            .append(",")
                            .append(String.valueOf(next.getValue()))
                            .append("\n");
                }

                System.out.println("Printed " + outputFile);
            } catch (FileNotFoundException ex) {
                System.err.println("Error printing " + outputFile + ". " + ex.getLocalizedMessage());
            }
        });

        Thread resourceWriter = new Thread(() -> {
            String outputFile = multipleInput ? "log_output/" + filename + "/resources.txt" : "log_output/resources.txt";

            try (PrintWriter pw = new PrintWriter(outputFile)) {
                int i = 0;

                Comparator<Map.Entry<String, Double>> comparatorResourceBandwith = (Map.Entry<String, Double> o1, Map.Entry<String, Double> o2) -> {
                    int res = o2.getValue().compareTo(o1.getValue());
                    return res != 0 ? res : o1.getKey().compareTo(o2.getKey());
                };

                List<Map.Entry<String, Double>> list = new LinkedList<>(resourceBandwith.entrySet());
                list.sort(comparatorResourceBandwith);

                Iterator<Map.Entry<String, Double>> iterator = list.iterator();
                while (iterator.hasNext() && elementsToPrint > i++) {
                    pw.append(iterator.next().getKey()).append("\n");
                }

                System.out.println("Printed " + outputFile);
            } catch (FileNotFoundException ex) {
                System.err.println("Error printing " + outputFile + ". " + ex.getLocalizedMessage());
            }
        });

        hostWriter.start();
        resourceWriter.start();

        String outputFile = multipleInput ? "log_output/" + filename + "/hours.txt" : "log_output/hours.txt";
        try (PrintWriter pw = new PrintWriter(outputFile)) {
            timeWindows.forEach((entry) -> {
                pw.append(entry.getLabel())
                        .append(",")
                        .append(String.valueOf(entry.getCounter()))
                        .append("\n");
            });

            System.out.println("Printed " + outputFile);
        }

        outputFile = multipleInput ? "log_output/" + filename + "/blocked.txt" : "log_output/blocked.txt";
        try (PrintWriter pw = new PrintWriter(outputFile)) {
            blocked.forEach((line) -> {
                pw.append(line).append("\n");
            });

            System.out.println("Printed " + outputFile);
        }

        try {
            hostWriter.join();
            resourceWriter.join();
        } catch (InterruptedException ex) {
            System.err.println("Error: Son threads died unexpectedly. " + ex.getLocalizedMessage());
        }

    }

    private boolean isValidTime(long limitTime, long recordTime) {
        return (limitTime - recordTime > 0);
    }

    private void addToFeature1(String host) {
        Integer currentValue = hostCounter.putIfAbsent(host, 1);
        if (currentValue != null) {
            hostCounter.replace(host, ++currentValue);
        }
    }

    private void addToFeature2(String bytes, String resource) {
        Double bandwidthValue = resourceBandwith.get(resource);
        bandwidthValue = (bandwidthValue == null) ? Double.parseDouble(bytes) / 1024 : (Double.parseDouble(bytes) / 1024) + bandwidthValue; // kb
        resourceBandwith.put(resource, bandwidthValue);
    }

    private void addToFeature3(String timestamp, int timeWindowCounter) {
        timeWindows.add(new Counter(timestamp, timeWindowCounter));
        if (timeWindows.size() > 10) {
            timeWindows.remove(timeWindows.last());
        }
    }

    private void addToFeature4(String host, long recordTime, String record, String resource, String responseCode) {
        Long endDate = bloquedHosts.get(host);
        if (endDate != null) {
            if (isValidTime(endDate, recordTime)) {
                blocked.add(record);
                return;
            } else {
                bloquedHosts.remove(host);
            }
        }

        if (resource.equals("/login")) {
            if (responseCode.equals("401")) {
                endDate = recordTime + loginAttemptsWindowTime;
                LoginFail loginFail = new LoginFail(1, endDate, host);

                LoginFail currentLoginFail = failedLogins.putIfAbsent(host, loginFail);
                if (currentLoginFail != null) {
                    if (isValidTime(endDate, currentLoginFail.getTimeLimit())) {
                        currentLoginFail.addToCounter();

                        if (currentLoginFail.getCounter() < maxLoginAttempts) {
                            failedLogins.replace(host, currentLoginFail);
                        } else {
                            failedLogins.remove(host);

                            endDate = recordTime + loginJailTime;
                            bloquedHosts.put(host, endDate);
                        }
                    } else {
                        failedLogins.replace(host, loginFail);
                    }
                }
            } else if (responseCode.equals("200")) {
                failedLogins.remove(host);
            }
        }
    }

    public void setMaxLoginAttempts(int maxLoginAttempts) {
        this.maxLoginAttempts = maxLoginAttempts;
    }

    public void setLoginJailTime_s(int loginJailTime_seconds) {
        loginJailTime = loginJailTime_seconds * 1000;
    }

    public void setLoginAttemptsWindowTime_s(int loginAttemptsWindowTime_seconds) {
        loginAttemptsWindowTime = loginAttemptsWindowTime_seconds * 1000;
    }

    public int getMaxLoginAttempts() {
        return maxLoginAttempts;
    }

    public int getLoginJailTime_s() {
        return loginJailTime / 1000;
    }

    public int getLoginAttemptsWindowTime_s() {
        return loginAttemptsWindowTime / 1000;
    }

    public static void main(String[] args) {
        System.out.println("Starting...");

        boolean skipRootResource = true; // "/"

        if (args.length == 1) {
            LogAnalyzer analyzer = new LogAnalyzer(skipRootResource);
            analyzer.process(args[0]);
        } else if (args.length > 1) {
            final boolean multipleInput = true;

            List<Thread> threadList = new ArrayList<>();
            Thread thread;
            for (String input : args) {
                thread = new Thread(() -> {
                    Thread.currentThread().setName(input);
                    new LogAnalyzer(skipRootResource, multipleInput).process(input);
                });

                threadList.add(thread);
                thread.start();
            }

            threadList.forEach((t) -> {
                try {
                    t.join();
                } catch (InterruptedException ex) {
                    System.err.println("Error on thread " + t.getName() + ". " + ex.getLocalizedMessage());
                }
            });
        } else {
            System.out.println("Usage: logAnalyzer.jar +input_files");
        }
    }

}
