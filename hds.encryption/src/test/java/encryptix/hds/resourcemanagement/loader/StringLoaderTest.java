package encryptix.hds.resourcemanagement.loader;

import encryptix.hds.exception.InvalidResourceFormat;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;
import encryptix.hds.keymanagement.loader.PublicKeyLoader;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.Security;

public class StringLoaderTest {

    @BeforeClass
    public static void initialize() {
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());
    }


    static String[] testStrings = {
            "",
            "testpwd",
            "c2837b4c038274tv5c0234tcv5-203v45245y3lk6m7bl34i5yvl234nro23845y928345c09238b79(**(^%^%#*^%&OYFLUYG()&%)*(YIYG)",
            "adfcasdfcasdfc\nq9374c298346\n\r2c3874cv5t29345tcv9v9^(&^%&(^\n\n\n"
    };

    @Test
    public void testHappyPathWithStringReader() throws IOException {
        for (String testString : testStrings) {
            Assert.assertEquals(
                    testString,
                    StringLoader.readString(new StringReader(testString))
            );
        }
    }

    @Test
    public void testReadFromFile() throws ResourceNotFound, IOException, ResourceReadFailed, InvalidResourceFormat {
        // yes, it's a crazy idea to test simple loader with encryption suite
        // nevertheless, we are in crypto-module and this is the easiest and reliable way to check that nothing was damaged
        Reader filerReader = new ClasspathResourceReader().getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem");
        String publicKeyString = StringLoader.readString(filerReader);
        Assert.assertNotNull(PublicKeyLoader.readPublicKey(new StringReader(publicKeyString)));
    }
}
