import org.w3c.dom.*;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.HashSet;
import java.util.Set;

public class NessusParser {

    public static Set<String> extractCVEs(String filePath) {
        Set<String> cves = new HashSet<>();
        try {
            File file = new File(filePath);
            Document doc = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder().parse(file);
            doc.getDocumentElement().normalize();

            NodeList reportItems = doc.getElementsByTagName("ReportItem");

            for (int i = 0; i < reportItems.getLength(); i++) {
                Node node = reportItems.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;
                    NodeList cveNodes = element.getElementsByTagName("cve");

                    for (int j = 0; j < cveNodes.getLength(); j++) {
                        String cve = cveNodes.item(j).getTextContent().trim();
                        if (cve.matches("CVE-\\d{4}-\\d{4,7}")) {
                            cves.add(cve);
                        }
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return cves;
    }
}
