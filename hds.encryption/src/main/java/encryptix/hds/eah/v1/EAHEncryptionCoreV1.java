
package encryptix.hds.eah.v1;

import encryptix.hds.eah.EAHEncryptionCore;
import encryptix.hds.exception.CryptoCoreFailed;
import encryptix.hds.exception.CryptoInitializationFailed;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.concurrent.TimeUnit;

// TODO: Randomize IV, use java.util.concurrent.ThreadLocalRandom and SecureRandom as a seed for performance

/**
 * EAH Encryption Core, V1 format
 * <p/>
 * This is CryptoCore for encryption by hybrid schema with ECIES and AES, see https://en.wikipedia.org/wiki/Hybrid_cryptosystem.
 * <p/>
 * To make key rotation easier and to get high performance on the top of BouncyCastle while massive processing,
 * was decided to use ECIES part (which is already hybrid) to store AES key and IV and encrypt data with this key and AES.
 * <p/>
 * Such ECIES part (which is time consuming) is cached and re-used for all rows in a "block", so we need to compute it
 * once per block and then use AES key and IV for the whole block for symmetric encryption, which is dramatically faster
 * because of AES is fast and usually hardware-backed.
 * <p/>
 * In general it's a typical hybrid schema, which was extended 'cause plain hybrid schema (like ECIES) is good to process
 * single big record, but in Hive we have a lot of small records. ECIES is used instead of plain ECC due to performance
 * and certified library available.
 * <p/>
 * So, in general, we sacrificed space (encrypted message is long) in favor of performance, security and readability. We
 * expected that asymmetric encryption on column-level will be used for most important data, the rest should be encrypted
 * on HDFS layer with AES and KMS infrastructure.
 * <p/>
 * NOTE ON IV: By our schema, IV will be also encrypted (which is not required), but shared among all records in a block
 * which is not recommended in general, but our situation is different. AES key - IV pair is randomly generated for a
 * block and IV is not re-used with other AES key. So please consider block as partitioned message.
 * <p/>
 * OUTPUT FORMAT:
 * Output is a human readable string (delimited and prefixed base64), format is
 * <p/>
 * format_identifier:format_version:asymmetric_encryption_part:symmetric_iv:symmetric_encryption_part
 * <p/>
 * format_identifier is a short label, which describes format, for example "eah"
 * format_version is a number, identifier of format version
 * asymmetric_encryption_part is base64-encoded ECIES part with EAS key and IV, shared over a block
 * symmetric_iv is a random initialization vector for CBC mode of symmetric encryption. Shared for block
 * symmetric_encryption_part is base64-encoded encrypted data part. Encrypted with AES256-CBC algorithm and AES key and IV,
 * from ECIES part
 * <p/>
 * So output will looks like eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=
 * <p/>
 * <b>
 * Target JVM is 7 with Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction installed, see
 * http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
 * <p/>
 * NOT threadsafe implementation, 'cause target is a Hive, which uses every instance in a single thread<b/>
 */
public class EAHEncryptionCoreV1 implements EAHEncryptionCore {

    /**
     * Maximum block size, rows. When X rows processed, block will be finished and new one started (new encryption key
     * and IV will be generated and cached as serialized ECIES part string)
     */
    public static final int DEFAULT_MAX_BLOCK_SIZE = 500000;

    private int maxBlockSize = DEFAULT_MAX_BLOCK_SIZE;

    /**
     * Minimum block size, rows. Block will not expire by time even when MAX_BLOCK_LIFETIME reached until MIN_BLOCK_SIZE
     * reached.
     * This is important to avoid situation when any waits after ECIES part initialization will be longer than ECIES
     * part lifetime, which will stop normal processing.
     */
    public static final int DEFAULT_MIN_BLOCK_SIZE = 10;

    private int minBlockSize = DEFAULT_MIN_BLOCK_SIZE;

    /**
     * Maximum cache/block life-time, in nanoseconds. After this time of _cached ECIES part usage (to exclude asymmetric
     * block generation time from TTL)_ AND after MIN_BLOCK_SIZE reached, block will be finished and new one started
     * (new encryption key and IV will be generated and cached as serialized ECIES string)
     */
    public static final long DEFAULT_MAX_BLOCK_LIFETIME = TimeUnit.NANOSECONDS.convert(500, TimeUnit.MILLISECONDS);

    private long maxBlockLifetime = DEFAULT_MAX_BLOCK_LIFETIME;

    /**
     * AES key size to encrypt data. Allowed values are 128, 192, 256 only
     */
    public static final int DEFAULT_AES_KEY_SIZE = 256;

    private int aesKeySize = DEFAULT_AES_KEY_SIZE;

    /**
     * AES Cipher definition, see
     * <p/>
     * http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
     * http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher
     * <p/>
     * Allowed values are "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding"
     * <p/>
     * AES/CBC/PKCS5Padding preferred, ECB need to be avoided until message length check and dynamic ECB-CBC switch used,
     * 'cause this mode should not be used for multiple blocks of data.
     */
    public static final String AES_CIPHER_TYPE = "AES/CBC/PKCS5Padding";

    /*
      Crypto engines
     */
    private Cipher aesEncryptCypher;
    private Cipher eciesEncryptCypher;
    private KeyGenerator aesKeyGenerator;

    /*
     Block cache
     */
    // Block prefix
    private String blockPrefix;
    // Block creation time
    private long blockECIESPartCreationTime;
    // Block statistic
    private int blockRowsProcessed;

    public EAHEncryptionCoreV1(PublicKey publicKey) throws CryptoInitializationFailed {
        initCore(publicKey);
    }

    public EAHEncryptionCoreV1(PublicKey publicKey, int minBlockSize, int maxBlockSize, long maxBlockLifetime, int aesKeySize) throws CryptoInitializationFailed {
        this(publicKey);
        this.maxBlockSize = maxBlockSize;
        this.minBlockSize = minBlockSize;
        this.maxBlockLifetime = maxBlockLifetime;
        this.aesKeySize = aesKeySize;
    }

    @SuppressWarnings("PMD.UselessParentheses") // minus variables for speed, plus ( ) for readability
    private boolean isReinitRequired() {
        return
                this.blockPrefix == null || // not initialized
                        blockRowsProcessed >= this.maxBlockSize || // max block size reached
                        (
                                blockRowsProcessed >= this.minBlockSize && // min block size reached AND
                                        (System.nanoTime() - this.blockECIESPartCreationTime > this.maxBlockLifetime) // lifetime timeout reached
                        );
    }

    /**
     * Init crypto core
     *
     * @param publicKey Public key for asymmetric part
     * @throws CryptoInitializationFailed If initialization filed, see root cause
     */
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "Exception detail hide")
    private void initCore(PublicKey publicKey) throws CryptoInitializationFailed {
        try {
            /*
             * Init ECC part
             */
            // Get ECIES Cipher
            this.eciesEncryptCypher = Cipher.getInstance("ECIES");
            // Init ECIES Cipher
            this.eciesEncryptCypher.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
            // Init AES key generator
            this.aesKeyGenerator = KeyGenerator.getInstance("AES");
            this.aesKeyGenerator.init(this.aesKeySize);
            // Generate AES key and store
            SecretKey secretAesKey = this.aesKeyGenerator.generateKey();
            byte[] aesKey = secretAesKey.getEncoded();
            // Encrypt it and store ECIES serialized part
            byte[] blockECIESPart = this.eciesEncryptCypher.doFinal(aesKey);

            /*
             * Init AES part
             */
            // Init initialization vector for CBC
            byte[] aesIV = new byte[16];
            (new SecureRandom()).nextBytes(aesIV);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(aesIV);
            // Get AES cipher
            this.aesEncryptCypher = Cipher.getInstance(AES_CIPHER_TYPE);
            // Init AES cipher with existing key and IV
            this.aesEncryptCypher.init(Cipher.ENCRYPT_MODE, secretAesKey, ivParameterSpec);

            // Create block prefix
            this.blockPrefix = FormatHelper.serializeBlockPrefix(blockECIESPart, aesIV);

        } catch (Exception e) {
            throw new CryptoInitializationFailed("Failed to initialize crypto core", e);
        }

        this.blockRowsProcessed = 0;
        this.blockECIESPartCreationTime = System.nanoTime();
    }

    /**
     * Re-init crypto core when block expired
     *
     * @throws CryptoInitializationFailed On re-init failed, see root cause
     */
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "Exception detail hide")
    private void reInitCore() throws CryptoInitializationFailed {
        try {

            /*
             * Re init ECC part
             */
            // Generate AES key and store
            SecretKey secretAesKey = aesKeyGenerator.generateKey();
            byte[] aesKey = secretAesKey.getEncoded();
            // Encrypt it and store ECIES serialized part
            byte[] blockECIESPart = this.eciesEncryptCypher.doFinal(aesKey);

            /*
             * Init AES part
             */
            // Init initialization vector for CBC
            byte[] aesIV = new byte[16];
            (new SecureRandom()).nextBytes(aesIV);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(aesIV);
            // Init AES cipher with existing key and IV
            this.aesEncryptCypher.init(Cipher.ENCRYPT_MODE, secretAesKey, ivParameterSpec);

            // Create block prefix
            this.blockPrefix = FormatHelper.serializeBlockPrefix(blockECIESPart, aesIV);

        } catch (Exception e) {
            throw new CryptoInitializationFailed("Failed to re-initialize crypto core", e);
        }

        this.blockRowsProcessed = 0;
        this.blockECIESPartCreationTime = System.nanoTime();
    }

    /**
     * Encrypt string to EAHv1 format with PublicKey
     *
     * @param value Value to encrypt
     * @return EAHv1 format string
     * @throws CryptoInitializationFailed
     * @throws CryptoCoreFailed
     */
    @Override
    public String encrypt(String value) throws CryptoInitializationFailed, CryptoCoreFailed {
        // check that encryption core is fresh
        if (isReinitRequired()) {
            reInitCore();
        }

        this.blockRowsProcessed++;

        try {
            return this.blockPrefix + FormatHelper.serialize(
                    this.aesEncryptCypher.doFinal(
                            FormatHelper.stringToBytes(value)
                    )
            );
        } catch (UnsupportedEncodingException e) {
            throw new CryptoCoreFailed("Crypto core failed on internal serialization, issues with charset supported ", e);
        } catch (BadPaddingException e) {
            throw new CryptoCoreFailed("Crypto core failed on encryption due to wrong padding", e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoCoreFailed("Crypto core failed on encryption due to wrong block size", e);
        }
    }

}
