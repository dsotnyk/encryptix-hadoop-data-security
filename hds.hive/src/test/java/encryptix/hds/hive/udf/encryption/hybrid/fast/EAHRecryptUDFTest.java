package encryptix.hds.hive.udf.encryption.hybrid.fast;

import encryptix.hds.exception.CryptoInitializationFailed;
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

public class EAHRecryptUDFTest {

    static EAHEncryptUDF defaultEncryptUDF;
    static EAHRecryptUDF defaultRecryptUDF;
    static EAHDecryptUDF defaultDecryptUDF;

    static ObjectInspector[] inputObjectInspector = {PrimitiveObjectInspectorFactory.javaStringObjectInspector};
    static WritableStringObjectInspector resultInspector;

    @BeforeClass
    static public void initialize() throws InternalInitException, UDFArgumentException, InstantiationException, IllegalAccessException {

        // Init encryption on aef803a00557fbef4ae3af4bf3836313
        cleanupSystemProperties();
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_public_key.pem");
        defaultEncryptUDF = new EAHEncryptUDF();
        defaultEncryptUDF.initialize(inputObjectInspector);

        // Init recryption from aef803a00557fbef4ae3af4bf3836313 to 47ed2bea86e8f4f9232f0659c1542818
        cleanupSystemProperties();
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_private_key_system_password.txt");
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem");
        defaultRecryptUDF = new EAHRecryptUDF();
        defaultRecryptUDF.initialize(inputObjectInspector);

        // Init decryption on 47ed2bea86e8f4f9232f0659c1542818
        cleanupSystemProperties();
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "classpath:eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_password.txt");
        defaultDecryptUDF = new EAHDecryptUDF();
        resultInspector = (WritableStringObjectInspector) defaultDecryptUDF.initialize(inputObjectInspector);

    }

    protected static void cleanupSystemProperties() {
        // clean-up properties
        System.clearProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE);
        System.clearProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE);
        System.clearProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE);
    }

    String udfEvaluate(GenericUDF udf, String input) throws HiveException {
        Object evaluationResult = udf.evaluate(new GenericUDF.DeferredObject[]{new GenericUDF.DeferredJavaObject(input)});
        return resultInspector.getPrimitiveJavaObject(evaluationResult);
    }

    @Test
    public void recryptHappyPath() throws HiveException {

        String message = "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme";

        String encryptedMessage = udfEvaluate(defaultEncryptUDF, message);
        String recryptedMessage = udfEvaluate(defaultRecryptUDF, encryptedMessage);
        String decryptedMessage = udfEvaluate(defaultDecryptUDF, recryptedMessage);

        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                decryptedMessage
        );
    }

    @Test(expected = InternalException.class)
    public void decryptWithWrongKey() throws HiveException {
        // value was encrypted with 3ccd72b3ba0e42f75994614603736f99. Recrypt configured to decrypt with aef803a00557fbef4ae3af4bf3836313
        udfEvaluate(defaultRecryptUDF, "eah:1:BAf5VKqSmvJNo7Fp91J93sDxRS3R83iwlOJfYKWubj0URUkrVgy+9PLEH7LuUc7x+9Wkzbc1dPK2uGowrwKo1d05jl5FNvEsYABUoNNp0d+p1YidFvS1fJhLBl6Q5v3vRNQJl2xZeZ9juxMhpK8JB0rwa+CRhqsDp/kEUsUd/h+SMQosfXIVknc2fJDW0geVZVILp3rTwhoo0KgypQIcEYCH5Rni3ZqYsaW3yPfpVKr1MZvCfkxpGX1hrk7HFPMBssjZdg4=:TRW6+/8o2e97PHuD9vSsog==:B869K/2bQs6PGf2BF1tWyOK/JnN4BJ3caYtc55zfdJhKPiqr8OR3kdddlpl+lJGgsC4HvnsIX36aopecZGk8FpeXCq2x1Ffo5QPKFwdVYo8=");
    }

    @Test(expected = WrongDataFormatException.class)
    public void decryptWrongEC() throws HiveException {
        Assert.assertEquals(
                "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                udfEvaluate(defaultRecryptUDF, "eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJJJJnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=")
        );
    }

    @Test
    public void stabilityTest() throws HiveException {
        int count = 10000;

        String message = "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme";

        String encryptedMessage = udfEvaluate(defaultEncryptUDF, message);

        for (int i = 0; i < count; i++) {
            String recryptedMessage = udfEvaluate(defaultRecryptUDF, encryptedMessage);
            String decryptedMessage = udfEvaluate(defaultDecryptUDF, recryptedMessage);

            Assert.assertEquals(
                    "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme",
                    decryptedMessage
            );
        }
    }

    @Test
    public void testNegativeMissingPrivateKey() {
        // set wrong key
        cleanupSystemProperties();
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/WRONG_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_private_key_system_password.txt");
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem");

        EAHRecryptUDF udf = new EAHRecryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // Analyze exception
            Assert.assertTrue(e.getCause() instanceof InternalInitException);
            Assert.assertTrue(e.getCause().getMessage().contains("Failed to find and open private key while initialization"));
        }
    }

    @Test
    public void testNegativeMissingKeyPassword() {
        // set wrong key
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "You'll never find such resource");
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem");

        EAHDecryptUDF udf = new EAHDecryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // Analyze exception
            Assert.assertTrue(e.getCause().getCause() instanceof CryptoInitializationFailed);
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("Found encrypted private key, but password wasn't provided"));
        }
    }

    @Test
    public void testNegativeWrongKeyPassword() {
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/aef803a00557fbef4ae3af4bf3836313_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "text:wrong");
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_public_key.pem");

        EAHDecryptUDF udf = new EAHDecryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // Analyze exception
            Assert.assertTrue(e.getCause().getCause() instanceof CryptoInitializationFailed);
            Assert.assertTrue(e.getCause().getCause().getMessage().contains("Found encrypted private key, but can't decrypt, is password wrong?"));
        }
    }

    @Test
    public void testPropertyFileLoad() throws UDFArgumentException {
        System.clearProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE);
        System.clearProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE);
        System.clearProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE);

        EAHDecryptUDF decryptUDF = new EAHDecryptUDF();
        EAHEncryptUDF encryptUDF = new EAHEncryptUDF();

        decryptUDF.initialize(inputObjectInspector);
        encryptUDF.initialize(inputObjectInspector);

    }

}
