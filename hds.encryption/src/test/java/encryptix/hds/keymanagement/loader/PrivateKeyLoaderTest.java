package encryptix.hds.keymanagement.loader;

import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import encryptix.hds.resourcemanagement.reader.ResourceReader;
import encryptix.hds.exception.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

public class PrivateKeyLoaderTest {

    static ResourceReader resourceReader = new ClasspathResourceReader();

    @BeforeClass
    public static void initialize() {
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Load unencrypted key with and without password
     */
    @Test
    public void testUnencryptedPrivateKeyLoadTest() throws ResourceNotFound, InvalidResourceFormat, CryptoInitializationFailed, ResourceReadFailed, InitializationFailed {
        Assert.assertNotNull(PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_unencrypted.pem")));
        Assert.assertNotNull(PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_unencrypted.pem"), null));
        Assert.assertNotNull(PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_unencrypted.pem"), "random"));
    }

    /**
     * Load non-existing key
     */
    @Test(expected = ResourceNotFound.class)
    public void testPrivateKeyLoadFailTest() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, CryptoInitializationFailed, InitializationFailed {
        PrivateKeyLoader.readPrivateKey(resourceReader.getResource("keys/not_found.pem"));
    }

    /**
     * Load encrypted key with correct password
     */
    @Test
    public void testEncryptedPrivateKeyLoadTest() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, CryptoInitializationFailed, InitializationFailed {
        Assert.assertNotNull(PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"), "testpwd"));
    }

    /**
     * Load encrypted key without password
     */
    @Test(expected = CryptoInitializationFailed.class)
    public void testEncryptedPrivateKeyNoPasswordLoadTest() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, CryptoInitializationFailed, InitializationFailed {
        Assert.assertNotNull(PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem")));
    }

    /**
     * Load encrypted key with incorrect password
     */
    @Test(expected = CryptoInitializationFailed.class)
    public void testEncryptedPrivateKeyWrongPasswordLoadTest() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, CryptoInitializationFailed, InitializationFailed {
        Assert.assertNotNull(PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"), "wrongpassword"));
    }


}
