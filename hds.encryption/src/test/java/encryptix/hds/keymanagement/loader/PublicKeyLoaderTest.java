package encryptix.hds.keymanagement.loader;

import encryptix.hds.exception.InitializationFailed;
import encryptix.hds.exception.InvalidResourceFormat;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import encryptix.hds.resourcemanagement.reader.ResourceReader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

public class PublicKeyLoaderTest {

    static ResourceReader resourceReader = new ClasspathResourceReader();

    @BeforeClass
    public static void initialize() {
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Load existing key
     */
    @Test
    public void testPublicKeyLoadTest() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, InitializationFailed {
        // Read Public Key
        Assert.assertNotNull(PublicKeyLoader.readPublicKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem")));
    }

    /**
     * Load non-existing key
     */
    @Test(expected = ResourceNotFound.class)
    public void testPublicKeyLoadFailTest() throws InvalidResourceFormat, ResourceReadFailed, ResourceNotFound, InitializationFailed {
        // Read Public Key
        PublicKeyLoader.readPublicKey(resourceReader.getResource("keys/not_found.pem"));
    }

}
