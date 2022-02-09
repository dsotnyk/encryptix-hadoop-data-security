
package encryptix.hds.eah.v1;

import encryptix.hds.exception.*;
import encryptix.hds.keymanagement.loader.PublicKeyLoader;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import encryptix.hds.resourcemanagement.reader.ResourceReader;
import encryptix.hds.exception.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.PublicKey;
import java.security.Security;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class EAHEncryptionCoreV1Test {

    static EAHEncryptionCoreV1 defaultEncryptionCore;

    static PublicKey publicKey;

    public static final String message = "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme";

    @BeforeClass
    public static void initialize() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, CryptoInitializationFailed, InitializationFailed {

        // Load EC library
        Security.addProvider(new BouncyCastleProvider());

        // Read Public Key
        ResourceReader resourceReader = new ClasspathResourceReader();
        publicKey = PublicKeyLoader.readPublicKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem"));

        defaultEncryptionCore = new EAHEncryptionCoreV1(publicKey);
    }

    /**
     * Check, that encryption works at all
     */
    @Test
    public void happyPassTest() throws CryptoCoreFailed, CryptoInitializationFailed {
        Assert.assertTrue(defaultEncryptionCore.encrypt(message).startsWith(FormatHelper.FORMAT_SIGNATURE));
    }

    /**
     * Check, that block survives minimum limit
     */
    @Test
    public void blockStabilityByMinLimitTest() throws CryptoInitializationFailed, CryptoCoreFailed, InterruptedException {
        EAHEncryptionCoreV1 encryptionCore = new EAHEncryptionCoreV1(publicKey, 10, 20, 1, 256);
        String encryptedMessage = encryptionCore.encrypt(message);
        Thread.sleep(10);

        // must be the same next 9 attempts
        for (int i = 1; i < 10; i++) {
            Assert.assertEquals(encryptedMessage, encryptionCore.encrypt(message));
        }

        // here need to be changed
        Assert.assertNotEquals(encryptedMessage, encryptionCore.encrypt(message));
    }

    /**
     * Check that block changed on maximum limit
     */
    @Test
    public void blockChangeByMaxLimitSimpleTest() throws CryptoInitializationFailed, CryptoCoreFailed, InterruptedException {
        EAHEncryptionCoreV1 encryptionCore = new EAHEncryptionCoreV1(publicKey, 10, 20, TimeUnit.NANOSECONDS.convert(500, TimeUnit.MILLISECONDS), 256);
        String encryptedMessage = encryptionCore.encrypt(message);

        // must be the same next 19 attempts
        for (int i = 1; i < 20; i++) {
            Assert.assertEquals(encryptedMessage, encryptionCore.encrypt(message));
        }

        // here need to be changed
        Assert.assertNotEquals(encryptedMessage, encryptionCore.encrypt(message));
    }

    /**
     * Check, that block changed by expiration time
     */
    @Test
    public void blockChangeByTimeSimpleTest() throws CryptoInitializationFailed, CryptoCoreFailed, InterruptedException {
        EAHEncryptionCoreV1 encryptionCore = new EAHEncryptionCoreV1(publicKey, 10, 20, TimeUnit.NANOSECONDS.convert(20, TimeUnit.MILLISECONDS), 256);
        String encryptedMessage = encryptionCore.encrypt(message);

        for (int i = 1; i < 15; i++) {
            Assert.assertEquals(encryptedMessage, encryptionCore.encrypt(message));
        }

        Thread.sleep(20);

        // here need to be changed
        Assert.assertNotEquals(encryptedMessage, encryptionCore.encrypt(message));
    }

    /**
     * Check that block stable changing on long run on max limit
     */
    @Test
    public void blockChangeSequenceByMaxLimitTest() throws CryptoInitializationFailed, CryptoCoreFailed {
        EAHEncryptionCoreV1 encryptionCore = new EAHEncryptionCoreV1(publicKey, 10, 20, TimeUnit.NANOSECONDS.convert(20000, TimeUnit.MILLISECONDS), 256);

        String oldEncryptedMessage = encryptionCore.encrypt(message);

        for (int i = 1; i < 200; i++) {
            String newEncryptedMessage = encryptionCore.encrypt(message);
            if (i % 20 == 0) {
                Assert.assertNotEquals(oldEncryptedMessage, newEncryptedMessage);
            } else {
                Assert.assertEquals(oldEncryptedMessage, newEncryptedMessage);
            }
            oldEncryptedMessage = newEncryptedMessage;
        }
    }

    /**
     * Check that block stable changing on long run on max time limit
     */
    @Test
    public void blockChangeSequenceByMaxTimeLimitTest() throws CryptoInitializationFailed, CryptoCoreFailed, InterruptedException {
        EAHEncryptionCoreV1 encryptionCore = new EAHEncryptionCoreV1(publicKey, 10, 20, TimeUnit.NANOSECONDS.convert(10, TimeUnit.MILLISECONDS), 256);

        String oldEncryptedMessage = encryptionCore.encrypt(message);

        // change block 5 times
        for (int step = 0; step < 5; step++) {

            // run from 10 to 18 times
            int maxRuns = 10 + new Random().nextInt(8);

            // enter block, it should be the same
            for (int i = 0; i < maxRuns; i++) {
                String newEncryptedMessage = encryptionCore.encrypt(message);
                Assert.assertEquals(oldEncryptedMessage, newEncryptedMessage);
                oldEncryptedMessage = newEncryptedMessage;
            }

            // wait block expiration
            Thread.sleep(11);

            // check that block changed
            String newEncryptedMessage = encryptionCore.encrypt(message);
            Assert.assertNotEquals(oldEncryptedMessage, newEncryptedMessage);
            oldEncryptedMessage = newEncryptedMessage;
        }
    }


}
