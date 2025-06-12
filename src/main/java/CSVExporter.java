import com.opencsv.CSVWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class CSVExporter {

    public static void export(List<CVEDetail> details, String fileName) {
        try (CSVWriter writer = new CSVWriter(new FileWriter(fileName))) {

            writer.writeNext(new String[]{
                    "CVE ID", "Severity", "Public Date", "CVSS Score",
                    "Product", "Package", "Advisory", "Fix State", "Description"
            });

            for (CVEDetail detail : details) {
                writer.writeNext(detail.toCSVRow());
            }

            System.out.println("Exported to " + fileName);
        } catch (IOException e) {
            System.out.println("Error exporting CSV: " + e.getMessage());
        }
    }
}
