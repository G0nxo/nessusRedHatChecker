import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;


import java.util.HashMap;
import java.util.Map;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class RedHatAPI {

    public static List<CVEDetail> fetchCVEDetails(String cve, String productFilter) {
        List<CVEDetail> details = new ArrayList<>();
        try {
            URL url = new URL("https://access.redhat.com/hydra/rest/securitydata/cve/" + cve + ".json");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Accept", "application/json");

            try (InputStream is = conn.getInputStream()) {
                JSONObject obj = new JSONObject(new JSONTokener(is));

                String severity = obj.optString("threat_severity", "N/A");
                String publicDate = obj.optString("public_date", "N/A");
                String cvssScore = obj.optJSONObject("cvss3") != null
                        ? obj.getJSONObject("cvss3").optString("cvss3_base_score", "N/A")
                        : "N/A";

                String description = obj.optJSONArray("details") != null
                        ? obj.optJSONArray("details").optString(0, "N/A")
                        : "N/A";
                Map<String, String> fixStateMap = new HashMap<>();
                JSONArray pkgStateArray = obj.optJSONArray("package_state");
                if (pkgStateArray != null) {
                    for (int i = 0; i < pkgStateArray.length(); i++) {
                        JSONObject ps = pkgStateArray.getJSONObject(i);
                        String product = ps.optString("product_name", "");
                        if (product.toLowerCase().contains(productFilter.toLowerCase())) {
                            CVEDetail detail = new CVEDetail(
                                    cve,
                                    severity,
                                    publicDate,
                                    cvssScore,
                                    product,
                                    ps.optString("package_name", "N/A"),
                                    "",
                                    ps.optString("fix_state", "Unknown"),
                                    description
                            );
                            details.add(detail);
                        }
                    }
                }


                JSONArray affected = obj.optJSONArray("affected_release");
                if (affected != null) {
                    for (int i = 0; i < affected.length(); i++) {
                        JSONObject item = affected.getJSONObject(i);
                        String product = item.optString("product_name", "");
                        if (product.toLowerCase().contains(productFilter.toLowerCase())) {
                            CVEDetail detail = new CVEDetail(
                                    cve,
                                    severity,
                                    publicDate,
                                    cvssScore,
                                    product,
                                    item.optString("package", "N/A"),
                                    item.optString("advisory", "N/A"),
                                    "",
                                    description
                            );
                            details.add(detail);
                        }
                    }
                }

            }
        } catch (Exception e) {
            System.out.println("Error retrieving CVE " + cve + ": " + e.getMessage());
        }
        return details;
    }

}
