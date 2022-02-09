package encryptix.hds.hive.udf.encryption.hybrid.fast;

import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.hive.exception.InternalException;
import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.exception.WrongDataFormatException;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.WritableStringObjectInspector;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;

public class EAHDecryptUDFTest {

    static EAHDecryptUDF defaultDecryptUDF;
    static ObjectInspector[] inputObjectInspector = {PrimitiveObjectInspectorFactory.javaStringObjectInspector};
    static WritableStringObjectInspector resultInspector;

    @BeforeClass
    static public void initialize() throws InternalInitException, UDFArgumentException {
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "text:testpwd");
        defaultDecryptUDF = new EAHDecryptUDF();
        resultInspector = (WritableStringObjectInspector) defaultDecryptUDF.initialize(inputObjectInspector);
    }

    String defaultUDFEvaluate(String input) throws HiveException {
        return UDFEvaluate(defaultDecryptUDF, input);
    }

    String UDFEvaluate(EAHDecryptUDF udf, String input) throws HiveException {
        Object evaluationResult = udf.evaluate(new GenericUDF.DeferredObject[]{new GenericUDF.DeferredJavaObject(input)});
        return resultInspector.getPrimitiveJavaObject(evaluationResult);
    }

    @Test(expected = InternalException.class)
    public void decryptWithWrongKey() throws HiveException {
        defaultUDFEvaluate("eah:1:BABdJIKX4kT2egMMiATLX9R3UGrccu8IyoTwvPGZKyKXU7vdcrysS+GMsvUcSFFsHWqZr5jcv2UAb6YXWMlprg8iA3vxnt7RxwAKNR8JEQh14KfLxYLRHUMtB1fBelHDYAVQJq3lBwWpxVylb1vK0VLO1pS3U+kI0sivKKb7wAQodChGZaNsjEhKnCtw6JQ0v9J/FwTfpiQFgJxy4oxRqeJqty5vGtMUQgja6cqX1cCV2Wj6Vg/TZyryCgop+y2PCmBabtE=:Uh90Z2UZS92xbB1x4y/3BQ==:V8J4W2t4aDbmwZup1MeFzEIKovb2A9ffWo/JNfcytVFq2GO8ydLgbFfL1KVoQo3HgPOzMNnyuc0AO26Cd+1d3MfH/J9d6bGlVKppyq3X3CM=");
    }

    @Test(expected = InternalException.class)
    public void decryptWithWrongKeyAndFalseFallback() throws HiveException {
        System.setProperty(EAHDecryptUDF.PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED, "false");
        EAHDecryptUDF udf = new EAHDecryptUDF();
        udf.initialize(inputObjectInspector);
        System.clearProperty(EAHDecryptUDF.PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED);

        UDFEvaluate(udf, "eah:1:BABdJIKX4kT2egMMiATLX9R3UGrccu8IyoTwvPGZKyKXU7vdcrysS+GMsvUcSFFsHWqZr5jcv2UAb6YXWMlprg8iA3vxnt7RxwAKNR8JEQh14KfLxYLRHUMtB1fBelHDYAVQJq3lBwWpxVylb1vK0VLO1pS3U+kI0sivKKb7wAQodChGZaNsjEhKnCtw6JQ0v9J/FwTfpiQFgJxy4oxRqeJqty5vGtMUQgja6cqX1cCV2Wj6Vg/TZyryCgop+y2PCmBabtE=:Uh90Z2UZS92xbB1x4y/3BQ==:V8J4W2t4aDbmwZup1MeFzEIKovb2A9ffWo/JNfcytVFq2GO8ydLgbFfL1KVoQo3HgPOzMNnyuc0AO26Cd+1d3MfH/J9d6bGlVKppyq3X3CM=");
    }

    @Test
    public void decryptWithWrongKeyAndTrueFallback() throws HiveException {
        System.setProperty(EAHDecryptUDF.PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED, "true");
        EAHDecryptUDF udf = new EAHDecryptUDF();
        udf.initialize(inputObjectInspector);
        System.clearProperty(EAHDecryptUDF.PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED);

        Assert.assertEquals(
                "eah:1:BABdJIKX4kT2egMMiATLX9R3UGrccu8IyoTwvPGZKyKXU7vdcrysS+GMsvUcSFFsHWqZr5jcv2UAb6YXWMlprg8iA3vxnt7RxwAKNR8JEQh14KfLxYLRHUMtB1fBelHDYAVQJq3lBwWpxVylb1vK0VLO1pS3U+kI0sivKKb7wAQodChGZaNsjEhKnCtw6JQ0v9J/FwTfpiQFgJxy4oxRqeJqty5vGtMUQgja6cqX1cCV2Wj6Vg/TZyryCgop+y2PCmBabtE=:Uh90Z2UZS92xbB1x4y/3BQ==:V8J4W2t4aDbmwZup1MeFzEIKovb2A9ffWo/JNfcytVFq2GO8ydLgbFfL1KVoQo3HgPOzMNnyuc0AO26Cd+1d3MfH/J9d6bGlVKppyq3X3CM=",
                UDFEvaluate(udf, "eah:1:BABdJIKX4kT2egMMiATLX9R3UGrccu8IyoTwvPGZKyKXU7vdcrysS+GMsvUcSFFsHWqZr5jcv2UAb6YXWMlprg8iA3vxnt7RxwAKNR8JEQh14KfLxYLRHUMtB1fBelHDYAVQJq3lBwWpxVylb1vK0VLO1pS3U+kI0sivKKb7wAQodChGZaNsjEhKnCtw6JQ0v9J/FwTfpiQFgJxy4oxRqeJqty5vGtMUQgja6cqX1cCV2Wj6Vg/TZyryCgop+y2PCmBabtE=:Uh90Z2UZS92xbB1x4y/3BQ==:V8J4W2t4aDbmwZup1MeFzEIKovb2A9ffWo/JNfcytVFq2GO8ydLgbFfL1KVoQo3HgPOzMNnyuc0AO26Cd+1d3MfH/J9d6bGlVKppyq3X3CM=")
        );
    }


    @Test
    public void decryptHappyPath() throws HiveException {
        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }

    @Test
    public void decryptWrongTextInTheBeginning() throws HiveException {
        Assert.assertNotEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:AAMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }

    @Test
    public void decryptWrongTextInTheMiddle() throws HiveException {
        Assert.assertNotEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAAAAkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }

    @Test(expected = InternalException.class)
    public void decryptWrongTextInTheEnd() throws HiveException {
        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzAdA=")
        );
    }

    @Test(expected = WrongDataFormatException.class)
    public void decryptWrongEC() throws HiveException {
        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJJJJnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }


    @Test
    public void decryptWrongIV() throws HiveException {
        Assert.assertNotEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zQ9Q9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }

    @Test
    public void stabilityTest() throws HiveException {
        int count = 10000;

        for (int i = 0; i < count; i++) {
            Assert.assertEquals(
                    "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                    defaultUDFEvaluate("eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
            );
        }
    }

    @Test
    public void testNegativeMissingKey() {
        // set wrong key
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "wrong_key");

        EAHDecryptUDF udf = new EAHDecryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // restore property
            System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_private_key_system_encrypted.pem");
            // Analyze exception
            Assert.assertTrue(e.getCause() instanceof InternalInitException);
            Assert.assertTrue(e.getCause().getMessage().contains("Failed to find and open private key while initialization"));
        }
    }

    @Test
    public void testNegativeMissingKeyPassword() {
        // set wrong key
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "wrong_password");

        EAHDecryptUDF udf = new EAHDecryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // restore property
            System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "text:testpwd");
            // Analyze exception
            Assert.assertTrue(e.getCause().getCause() instanceof CryptoInitializationFailed);
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("Found encrypted private key, but password wasn't provided"));
        }
    }

    @Test
    public void testNegativeWrongKeyPassword() {
        // set wrong key
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "text:wrong_password");

        EAHDecryptUDF udf = new EAHDecryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // restore property
            System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "text:testpwd");
            // Analyze exception
            Assert.assertTrue(e.getCause().getCause() instanceof CryptoInitializationFailed);
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("Found encrypted private key, but can't decrypt, is password wrong?"));
        }
    }

    @Test
    public void initKeyAndPasswordFromFile() throws ResourceNotFound, IOException, UDFArgumentException {
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_private_key_system_password.txt");
        EAHDecryptUDF udf = new EAHDecryptUDF();
        resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
    }

    @Test
    public void initUnencryptedKeyFromFile() throws ResourceNotFound, IOException, UDFArgumentException {
        System.clearProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE);
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_private_key_unencrypted.pem");

        EAHDecryptUDF udf = new EAHDecryptUDF();
        resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
    }


}
