package encryptix.hds.hive.udf.encryption.hybrid.fast;

import encryptix.hds.hive.exception.InternalInitException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.WritableStringObjectInspector;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class EAHCryptoSuiteUDFSTest {

    static EAHEncryptUDF encryptUDF;
    static EAHDecryptUDF decryptUDF;
    static ObjectInspector[] inputObjectInspector = {PrimitiveObjectInspectorFactory.javaStringObjectInspector};
    static WritableStringObjectInspector encryptResultInspector;
    static WritableStringObjectInspector decryptResultInspector;
    public static final String message = "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme";

    @BeforeClass
    static public void initialize() throws InternalInitException, UDFArgumentException {
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_public_key.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_private_key_system_encrypted.pem");
        System.setProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_private_key_system_password.txt");
        encryptUDF = new EAHEncryptUDF();
        decryptUDF = new EAHDecryptUDF();
        encryptResultInspector = (WritableStringObjectInspector) encryptUDF.initialize(inputObjectInspector);
        decryptResultInspector = (WritableStringObjectInspector) decryptUDF.initialize(inputObjectInspector);
    }

    String encryptUdfEvaluate(String input) throws HiveException {
        Object evaluationResult = encryptUDF.evaluate(new GenericUDF.DeferredObject[]{new GenericUDF.DeferredJavaObject(input)});
        return encryptResultInspector.getPrimitiveJavaObject(evaluationResult);
    }

    String decryptUdfEvaluate(String input) throws HiveException {
        Object evaluationResult = decryptUDF.evaluate(new GenericUDF.DeferredObject[]{new GenericUDF.DeferredJavaObject(input)});
        return decryptResultInspector.getPrimitiveJavaObject(evaluationResult);
    }

    @Test
    public void happyPath() throws HiveException {
        Assert.assertEquals(
                message,
                decryptUdfEvaluate(
                        encryptUdfEvaluate(message)
                )
        );
    }

    @Test
    public void stabilityTest() throws HiveException {
        int count = 10000;

        // Generate test messages
        List<String> testMessages = new ArrayList<>(count);

        for (int i = 0; i < count; i++) {
            testMessages.add(RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500)));
        }

        // Run test
        for (String testMessage : testMessages) {
            Assert.assertEquals(
                    testMessage,
                    decryptUdfEvaluate(
                            encryptUdfEvaluate(testMessage)
                    )
            );
        }
    }


}
