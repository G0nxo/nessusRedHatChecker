import com.opencsv.CSVWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class CSVExporter {

    public static void export(List<CVEDetail> details, String fileName) {
        try (CSVWriter writer = new CSVWriter(new FileWriter(fileName))) {
            String[] header = {
                    "CVE ID", "Severity", "Public Date", "CVSS Score", "Product Name", "Package", "Advisory", "Fix State", "Description"
            };
            writer.writeNext(header);

            for (CVEDetail detail : details) {
                writer.writeNext(detail.toCSVRow());
            }

            System.out.println("Exported to " + fileName);
        } catch (IOException e) {
            System.out.println("Error while exporting CSV: " + e.getMessage());
        }
    }
}
