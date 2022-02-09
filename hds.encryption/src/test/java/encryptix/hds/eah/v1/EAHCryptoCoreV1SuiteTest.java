package encryptix.hds.eah.v1;

import encryptix.hds.exception.*;
import encryptix.hds.keymanagement.loader.PrivateKeyLoader;
import encryptix.hds.keymanagement.loader.PublicKeyLoader;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import encryptix.hds.resourcemanagement.reader.ResourceReader;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Combined test for EAHv1 Crypto Engine
 */
public class EAHCryptoCoreV1SuiteTest {

    static EAHEncryptionCoreV1 defaultEncryptionCore;
    static EAHDecryptionCoreV1 defaultDecryptionCore;

    static PublicKey publicKey;
    static PrivateKey privateKey;

    @BeforeClass
    public static void initialize() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, CryptoInitializationFailed, InitializationFailed {

        // Load EC library
        Security.addProvider(new BouncyCastleProvider());

        // Read Public Key
        ResourceReader resourceReader = new ClasspathResourceReader();
        publicKey = PublicKeyLoader.readPublicKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem"));

        // Read Private Key
        privateKey = PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"), "testpwd");

        defaultEncryptionCore = new EAHEncryptionCoreV1(publicKey);
        defaultDecryptionCore = new EAHDecryptionCoreV1(privateKey);
    }

    /**
     * Simple encrypt-decrypt test with random value
     */
    @Test
    public void happyPathTest() throws CryptoCoreFailed, CryptoInitializationFailed, InvalidInputFormat {

        String message = RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500));

        Assert.assertEquals(
                message,
                defaultDecryptionCore.decrypt(defaultEncryptionCore.encrypt(message))
        );
    }

    /**
     * Simple encrypt-decrypt test with random value, N times run
     */
    @Test
    public void simpleStabilityTest() throws CryptoCoreFailed, CryptoInitializationFailed, InvalidInputFormat {

        final int testCount = 1000;

        for (int i = 0; i < testCount; i++) {
            String message = RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500));

            Assert.assertEquals(
                    message,
                    defaultDecryptionCore.decrypt(defaultEncryptionCore.encrypt(message))
            );
        }
    }

    /**
     * Randomized stability test, large block of random data
     */
    @Test
    public void randomizedStabilityTest() throws CryptoCoreFailed, CryptoInitializationFailed, InvalidInputFormat {

        final int testCount = 100000;

        // generate messages
        List<String> messages = new ArrayList<>(testCount);

        for (int i = 0; i < testCount; i++) {
            messages.add(RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500)));
        }

        // encrypt
        Map<String, String> encryptedMessages = new HashMap<>();

        for (String message : messages) {
            encryptedMessages.put(message, defaultEncryptionCore.encrypt(message));
        }

        // decrypt and compare
        for (Map.Entry<String, String> encryptedMessage : encryptedMessages.entrySet()) {
            Assert.assertEquals(
                    encryptedMessage.getKey(),
                    defaultDecryptionCore.decrypt(encryptedMessage.getValue())
            );
        }
    }


    /**
     * Randomized stability and performance test, extra large block of random data
     */
    @Test
    @Ignore
    public void longRandomizedPerformanceTest() throws CryptoCoreFailed, CryptoInitializationFailed, InvalidInputFormat {

        final long BLOCK_ENCRYPTION_TPS_MIN_THRESHOLD = 120000;
        final long TOTAL_ENCRYPTION_TPS_MIN_THRESHOLD = 120000;
        final long BLOCK_DECRYPTION_TPS_MIN_THRESHOLD = 120000;
        final long TOTAL_DECRYPTION_TPS_MIN_THRESHOLD = 120000;

        long totalEncryptionTime = 0;
        long totalDecryptionTime = 0;
        long totalRecordsEncrypted = 0;
        long totalRecordsDecrypted = 0;

        final int BLOCK_TESTS_COUNT = 1000 * 1000;
        final int MAX_TESTS_COUNT = 1000 * 1000 * 1000;

        while (totalRecordsDecrypted <= MAX_TESTS_COUNT) {

            long startTime, runTime;

            // Generate test messages
            List<String> messages = new ArrayList<>(BLOCK_TESTS_COUNT);

            for (int i = 0; i < BLOCK_TESTS_COUNT; i++) {
                messages.add(RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500)));
            }

            // encrypt
            Map<String, String> encryptedMessages = new HashMap<>();

            startTime = System.nanoTime();
            for (String message : messages) {
                encryptedMessages.put(message, defaultEncryptionCore.encrypt(message));
            }

            // report block encrypt statistic and compare threshold
            runTime = System.nanoTime() - startTime;
            totalEncryptionTime += runTime;
            totalRecordsEncrypted += BLOCK_TESTS_COUNT;
            System.out.println("Encrypted " + BLOCK_TESTS_COUNT + " records in " + runTime / 1000 / 1000 + " msecs, single record " + (runTime / BLOCK_TESTS_COUNT) + " nanosecs, tps " + (TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (runTime / BLOCK_TESTS_COUNT)));
            Assert.assertTrue((TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (runTime / BLOCK_TESTS_COUNT)) > BLOCK_ENCRYPTION_TPS_MIN_THRESHOLD);

            // decrypt and compare
            startTime = System.nanoTime();
            for (Map.Entry<String, String> encryptedMessage : encryptedMessages.entrySet()) {
                Assert.assertEquals(
                        encryptedMessage.getKey(),
                        defaultDecryptionCore.decrypt(encryptedMessage.getValue())
                );
            }

            // report block decrypt statistic and compare threshold
            runTime = System.nanoTime() - startTime;
            totalDecryptionTime += runTime;
            totalRecordsDecrypted += BLOCK_TESTS_COUNT;
            System.out.println("Decrypted " + BLOCK_TESTS_COUNT + " records in " + runTime / 1000 / 1000 + " msecs, single record " + (runTime / BLOCK_TESTS_COUNT) + " nanosecs, tps " + (TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (runTime / BLOCK_TESTS_COUNT)));
            Assert.assertTrue((TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (runTime / BLOCK_TESTS_COUNT)) > BLOCK_DECRYPTION_TPS_MIN_THRESHOLD);

            // Write totals and compare thresholds
            System.out.println("TOTAL Encrypted " + totalRecordsEncrypted + " records in " + totalEncryptionTime / 1000 / 1000 + " msecs, single record " + (totalEncryptionTime / totalRecordsEncrypted) + " nanosecs, tps " + (TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (totalEncryptionTime / totalRecordsEncrypted)));
            System.out.println("TOTAL Decrypted " + totalRecordsDecrypted + " records in " + totalDecryptionTime / 1000 / 1000 + " msecs, single record " + (totalDecryptionTime / totalRecordsDecrypted) + " nanosecs, tps " + (TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (totalDecryptionTime / totalRecordsDecrypted)));
            Assert.assertTrue((TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (totalEncryptionTime / totalRecordsEncrypted)) > TOTAL_ENCRYPTION_TPS_MIN_THRESHOLD);
            Assert.assertTrue((TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) / (totalDecryptionTime / totalRecordsDecrypted)) > TOTAL_DECRYPTION_TPS_MIN_THRESHOLD);
        }
    }


}
