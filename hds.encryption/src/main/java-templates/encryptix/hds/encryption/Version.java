package encryptix.hds.encryption;

/**
 * Package version
 */
public final class Version {
    private static final String GROUP_ID = "${project.groupId}";
    private static final String ARTIFACT_ID = "${project.artifactId}";
    private static final String VERSION = "${project.version}";

    public static String getGROUPID() {
        return GROUP_ID;
    }

    public static String getARTIFACTID() {
        return ARTIFACT_ID;
    }

    public static String getVERSION() {
        return VERSION;
    }

    public static void main(String[] args) {
        System.out.println(getPackageIdentifier());
    }

    public static String getPackageIdentifier() {
        return GROUP_ID + ":" + ARTIFACT_ID + ":" + VERSION;
    }
}