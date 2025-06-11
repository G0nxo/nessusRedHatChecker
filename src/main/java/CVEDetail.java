public class CVEDetail {

    private String cvdId;
    private String severity;
    private String publicDate;
    private String cvssScore;
    private String productName;
    private String packageName;
    private String advisory;
    private String fixState;
    private String description;

    public CVEDetail(String cvdId, String severity, String publicDate, String cvssScore,
                     String productName, String packageName, String advisory, String fixState, String description) {
        this.cvdId = cvdId;
        this.severity = severity;
        this.publicDate = publicDate;
        this.cvssScore = cvssScore;
        this.productName = productName;
        this.packageName = packageName;
        this.advisory = advisory;
        this.fixState = fixState;
        this.description = description;
    }

    public String getCvdId() {
        return cvdId;
    }

    public void setCvdId(String cvdId) {
        this.cvdId = cvdId;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getPublicDate() {
        return publicDate;
    }

    public void setPublicDate(String publicDate) {
        this.publicDate = publicDate;
    }

    public String getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(String cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getAdvisory() {
        return advisory;
    }

    public void setAdvisory(String advisory) {
        this.advisory = advisory;
    }

    public String getFixState() {
        return fixState;
    }

    public void setFixState(String fixState) {
        this.fixState = fixState;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String[] toCSVRow() {
        return new String[]{cvdId, severity, publicDate, cvssScore, productName, packageName, advisory, fixState, description};
    }
}
