import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

public class Main {

    public static void main(String[] args) throws IOException {
        Scanner sc = new Scanner(System.in);

        System.out.println("Enter the path of the .nessus file: ");
        String path = sc.nextLine().trim();

        System.out.println("Enter the name of the Red Hat product (ex. Red Hat Enterprise Linux 7): ");
        String productName = sc.nextLine().trim();

        List<String> cves;
        try {
            Set<String> cveSet = NessusParser.extractCVEs(path);
            cves = new ArrayList<>(cveSet);
            System.out.println("Found CVEs: " + cves.size());
        } catch (Exception e) {
            System.out.println("Error reading .nessus file: " + e.getMessage());
            return;
        }

        List<CVEDetail> results = new ArrayList<>();

        int total = cves.size();

        for (int i = 0; i < total; i++) {
            String cve = cves.get(i);

            int percent = (i + 1) * 100 / total;
            int completed = percent / 10;
            int remaining = 10 - completed;

            String bar = "[" + "#".repeat(completed) + "-".repeat(remaining) + "] "
                    + (i + 1) + "/" + total + " (" + percent + "%) " + cve;

            System.out.print("\r" + bar);

            List<CVEDetail> detailList = RedHatAPI.fetchCVEDetails(cve, productName);
            results.addAll(detailList);

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println();

        if (!results.isEmpty()) {
            CSVExporter.export(results, "results.csv");
            System.out.println("Exported to results.csv");
        } else {
            System.out.println("No results found.");
        }
    }
}
