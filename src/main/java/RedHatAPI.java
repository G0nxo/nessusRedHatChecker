import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class RedHatAPI {
    public static CVEDetail fetchCVEDetail(String cveId, String productFilter) throws IOException {
        try {
            String urlString = "https://access.redhat.com/hydra/rest/securitydata/cve/" + cveId + ".json";
            URL url = new URL(urlString);

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() != 200) {
                System.out.println("Error: " + conn.getResponseMessage());
                System.out.println("Error: couldn't find information for: " + cveId);
                return null;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder jsonText = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonText.append(line);
            }
            reader.close();

            JSONObject jsonObject = new JSONObject(jsonText.toString());

            String severity = jsonObject.optString("threat_severity", "N/A");
            String publicDate = jsonObject.optString("public_date", "N/A");
            String cvssScore = jsonObject.has("cvss3") ? jsonObject.getJSONObject("cvss3").optString("cvss3_base_score", "N/A") : "N/A";
            String description = jsonObject.has("bugzilla") ? jsonObject.getJSONObject("bugzilla").optString("description", "N/A") : "N/A";

            JSONArray affectedReleases = jsonObject.optJSONArray("affected_release");
            if (affectedReleases != null) {
                for (int i = 0; i < affectedReleases.length(); i++) {
                    JSONObject rel = affectedReleases.getJSONObject(i);
                    String productName = rel.optString("product_name");
                    if (productName != null && productName.toLowerCase().contains(productFilter.toLowerCase())) {
                        return new CVEDetail(
                                cveId,
                                severity,
                                publicDate,
                                cvssScore,
                                productName,
                                rel.optString("package", "N/A"),
                                rel.optString("advisory", "N/A"),
                                "N/A",
                                description
                        );
                    }
                }
            }

            JSONArray packageStates = jsonObject.optJSONArray("package_state");
            if (packageStates != null) {
                for (int i = 0; i < packageStates.length(); i++) {
                    JSONObject pkg = packageStates.getJSONObject(i);
                    String productName = pkg.optString("product_name");
                    if (productName != null && productName.toLowerCase().contains(productFilter.toLowerCase())) {
                        return new CVEDetail(
                                cveId,
                                severity,
                                publicDate,
                                cvssScore,
                                productName,
                                pkg.optString("package_name", "N/A"),
                                "N/A",
                                pkg.optString("fix_state", "N/A"),
                                description
                        );
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Error processing " + cveId + ": " + e.getMessage());
        }
        return null;
    }
}
