package encryptix.hds.eah.v1;

import encryptix.hds.eah.EAHDecryptionCore;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import encryptix.hds.exception.CryptoCoreFailed;
import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.exception.InvalidInputFormat;

/**
 * EAH Decryption Core, V1 format
 *
 * @see EAHEncryptionCoreV1
*/
//@edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "SIC_INNER_SHOULD_BE_STATIC_ANON", justification = "Will be replaced later with LRU cache")
public class EAHDecryptionCoreV1 implements EAHDecryptionCore {

    /**
     * Size of the L2 cache for AES keys
     */
    public static final int AES_KEY_CACHE_SIZE = 1000;

    /*
      Crypto engines
     */
    private transient Cipher aesDecryptCypher;
    private transient Cipher eciesDecryptCypher;

    /*
      Caches
     */
    //  Level 1 Cache
    private String lastEciesPartString = null;
    private SecretKey lastAesKey = null;
    private String lastAesIVString = null;
    private IvParameterSpec lastAesIV = null;

    // Level 2 Cache of AES keys
    // TODO Back or replace with true LRU cache
    private Map<String, SecretKey> aesKeyCacheL2 = new LinkedHashMap<String, SecretKey>(AES_KEY_CACHE_SIZE + 1, 1F, true) {
        public boolean removeEldestEntry(Map.Entry eldest) {
            return size() > AES_KEY_CACHE_SIZE;
        }
    };

    public EAHDecryptionCoreV1(PrivateKey privateKey) throws CryptoInitializationFailed {
        initCore(privateKey);
    }

    /**
     * Init crypto core
     *
     * @param privateKey Private key for asymmetric part
     * @throws CryptoInitializationFailed If initialization filed, see root cause
     */
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "Exception detail hide")
    private void initCore(PrivateKey privateKey) throws CryptoInitializationFailed {
        try {

            // Get ECIES Cipher
            this.eciesDecryptCypher = Cipher.getInstance("ECIES");
            // Init ECIES Cipher
            this.eciesDecryptCypher.init(Cipher.DECRYPT_MODE, privateKey, new SecureRandom());

            /*
             * Init AES part
             */
            // Get AES cipher
            this.aesDecryptCypher = Cipher.getInstance(EAHEncryptionCoreV1.AES_CIPHER_TYPE);
        } catch (Exception e) {
            throw new CryptoInitializationFailed("Failed to initialize crypto core", e);
        }
    }

    /**
     * Decrypt AEHv1 format with Private Key
     *
     * @param value EAH String
     * @return decrypted value
     *
     * @throws CryptoInitializationFailed
     * @throws CryptoCoreFailed
     * @throws InvalidInputFormat
     */
    @Override
    public String decrypt(String value) throws CryptoInitializationFailed, CryptoCoreFailed, InvalidInputFormat {

        try {
            /*
              We need to be extremely quick, see
              http://programmers.stackexchange.com/questions/221997/quickest-way-to-split-a-delimited-string-in-java
              Nevertheless, at least in Java 7, split by single char will fallback to indexOf
             */
            String[] blocks = value.split(FormatHelper.SERIALIZED_BLOCK_DELIMITER);

            // for V1 message format is IDENTIFIER_PREFIX : VERSION : ECIESPart : aesIV : encrypted data
            // for V1 we need to parse ECIESPart [2], aesIV [3], encrypted data [4]
            // We will NOT check prefix or version (@see FormatHelper.FORMAT_SIGNATURE) due to time, if it decrypted - ok.
            // Top layer is responsible for this, @see EAHDecrypteUDF
            if (blocks.length != 5) {
                throw new InvalidInputFormat("Encrypted message is wrong, no enough blocks (5 expected) for the version 1 in value " + value);
            }

            /*
              Well, we can use some kind of parser and DTO blah-blah. Nevertheless, I need to process billion records
              with more than 200K TpS , so every microsecond is important and every memory byte

              So, we just have to keep in mind simple format schema
              signatureString = block[0]
              formatVersionString = block[1]
              eciesPartString = blocks[2];
              aesIVString = blocks[3];
              encryptedDataString = blocks[4];
            */
            return new String(decrypt(blocks[2], blocks[3], blocks[4]), FormatHelper.CONVERSION_CHARSET);
        } catch (BadPaddingException e) {
            throw new CryptoCoreFailed("Crypto core failed on decryption due to wrong padding, value " + value, e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoCoreFailed("Crypto core failed on decryption due to wrong block size, value " + value, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoCoreFailed("Crypto core failed on decryption due to wrong algorithm parameter, value " + value, e);
        } catch (InvalidKeyException e) {
            throw new CryptoCoreFailed("Crypto core failed on decryption due to wrong decription key, value " + value, e);
        } catch (IllegalArgumentException e) {
            throw new InvalidInputFormat("EAH v1 format is wrong, failed to deserialize value" + value, e);
        }
    }

    /**
     * Deserialize and de-crypt EAH message.
     * The reason why we have no method with byte[] parameters is that we are deserializing ESIES and IV data only if
     * we've missed L1-L2 caches, so let crypto engine to decide is it need deserialization on not.
     * This is microseconds, but this is 150K tps vs 200K tps.
     *
     * @param eciesPartString ECIES part of the schema
     * @param aesIVString AES IV part
     * @param encryptedDataString AES encrypted data
     * @return Decrypted data
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public byte[] decrypt(String eciesPartString, String aesIVString, String encryptedDataString) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        /*
         PLEASE DO NOT CHANGE CACHING LOGIC UNTIL YOU ARE ABSOLUTELY SURE WHAT YOU DO
         THIS SEQUENCE OF THE OPERATIONS WAS CREATED TO TO PRESERVER NANOSECONDS AFTER MASSIVE PERFORMANCE TESTS
         */

        // Hey, I have a special stree^W cache magic for you

        // Check, is IV changed
        boolean isIVChanged = !aesIVString.equals(this.lastAesIVString);
        // Check is ECIES part changed. We can't rely on IV 'cause IV can have collisions and be same for different blocks
        boolean isECIESChanged = !eciesPartString.equals(this.lastEciesPartString);

        // Time to update ECIES
        if (isECIESChanged) {
            // let's look in L2 Cache
            SecretKey aesKey = aesKeyCacheL2.get(eciesPartString);
            // if L2 miss - decrypt and update L2
            if (aesKey == null) {
                // decrypt
                // Deserialize only here
                byte[] aesKeyBytes = this.eciesDecryptCypher.doFinal(FormatHelper.deserialize(eciesPartString));
                // create key
                aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");

                // Well, let's update L2 cache
                aesKeyCacheL2.put(eciesPartString, aesKey);
            }

            // now update L1 cache
            this.lastAesKey = aesKey;
            this.lastEciesPartString = eciesPartString;
        }

        // Time to update IV cache
        if (isIVChanged) {
            // Update L1 cache
            // Deserialize only here
            this.lastAesIV = new IvParameterSpec(FormatHelper.deserialize(aesIVString));
            this.lastAesIVString = aesIVString;
        }


        // DEFECT FOUND IN JAVA AES. We MUST re-init Cypher on every decryption, 'cause if previous cryptotext padding
        // was damaged in the padding zone, this will left AES Cipher in wrong state and next Cypher, first block, will
        // be decrypted incorrectly.
        /*
        // If decryption parameters changed - update Cipher
        if (isECIESChanged || isIVChanged) {
            this.aesDecryptCypher.init(Cipher.DECRYPT_MODE, this.lastAesKey, this.lastAesIV);
        }
        */
        this.aesDecryptCypher.init(Cipher.DECRYPT_MODE, this.lastAesKey, this.lastAesIV);

        return this.aesDecryptCypher.doFinal(FormatHelper.deserialize(encryptedDataString));
    }
}
