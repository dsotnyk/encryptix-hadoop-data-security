package encryptix.hds.hash;

import encryptix.hds.exception.CryptoInitializationFailed;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This is simple digest generator which is NOT THREAD-SAFE,but reuses MessageDigest object, so fast enough
 * Good for single-thread processing of massive data
 */
public class StreamedDigestGenerator {
    // few nanoseconds on lookup
    static Charset defaultCharset = Charset.forName("UTF-8");

    MessageDigest digest;

    public StreamedDigestGenerator(DigestAlgorithm digestAlgorithm) throws CryptoInitializationFailed {
        try {
            this.digest = MessageDigest.getInstance(digestAlgorithm.getAlgorithmName());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoInitializationFailed("Digest algorithm "+digestAlgorithm.getAlgorithmName()+" is not supported");
        }
    }

    public byte[] digest(byte[] input) {
        return this.digest.digest(input);
    }

    public String hexDigest(byte[] input) {
        return new String(Hex.encode(this.digest(input)), defaultCharset);
    }

    public String hexDigest(String input) {
        return hexDigest(input.getBytes(defaultCharset));
    }
}
