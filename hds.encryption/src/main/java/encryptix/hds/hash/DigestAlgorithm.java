package encryptix.hds.hash;

/**
 * Available algorithms, since out target JVM is Java 7, we are following
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest
 */
public enum DigestAlgorithm {

    MD2, MD5, SHA1("SHA-1"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512");

    private String algorithmName;

    DigestAlgorithm() {
        this.algorithmName = this.name();
    }

    DigestAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }
}
