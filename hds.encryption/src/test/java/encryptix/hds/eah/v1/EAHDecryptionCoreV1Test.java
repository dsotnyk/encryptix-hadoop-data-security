package encryptix.hds.eah.v1;

import encryptix.hds.exception.*;
import encryptix.hds.keymanagement.loader.PrivateKeyLoader;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import encryptix.hds.resourcemanagement.reader.ResourceReader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import java.security.*;

public class EAHDecryptionCoreV1Test {

    static EAHDecryptionCoreV1 defaultDecryptionCore;

    static PrivateKey privateKey;

    @BeforeClass
    public static void initialize() throws CryptoInitializationFailed, ResourceReadFailed, InvalidResourceFormat, ResourceNotFound, InitializationFailed {
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());

        // Read Private Key
        ResourceReader resourceReader = new ClasspathResourceReader();
        privateKey = PrivateKeyLoader.readPrivateKey(resourceReader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"), "testpwd");

        defaultDecryptionCore = new EAHDecryptionCoreV1(privateKey);
    }

    /**
     * Simple test to decrypt static EAHv1 message
     */
    @Test
    public void happyPassTest() throws CryptoInitializationFailed, CryptoCoreFailed, InvalidInputFormat {
        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultDecryptionCore.decrypt("eah:1:BABdJIKX4kT2egMMiATLX9R3UGrccu8IyoTwvPGZKyKXU7vdcrysS+GMsvUcSFFsHWqZr5jcv2UAb6YXWMlprg8iA3vxnt7RxwAKNR8JEQh14KfLxYLRHUMtB1fBelHDYAVQJq3lBwWpxVylb1vK0VLO1pS3U+kI0sivKKb7wAQodChGZaNsjEhKnCtw6JQ0v9J/FwTfpiQFgJxy4oxRqeJqty5vGtMUQgja6cqX1cCV2Wj6Vg/TZyryCgop+y2PCmBabtE=:Uh90Z2UZS92xbB1x4y/3BQ==:V8J4W2t4aDbmwZup1MeFzEIKovb2A9ffWo/JNfcytVFq2GO8ydLgbFfL1KVoQo3HgPOzMNnyuc0AO26Cd+1d3MfH/J9d6bGlVKppyq3X3CM=")
        );
    }

    /**
     * Simple test to decrypt static EAHv1 message with wrong key
     */
    @Test(expected = CryptoCoreFailed.class)
    public void wrongKeyTest() throws CryptoInitializationFailed, CryptoCoreFailed, InvalidInputFormat {
        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultDecryptionCore.decrypt("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }

}
