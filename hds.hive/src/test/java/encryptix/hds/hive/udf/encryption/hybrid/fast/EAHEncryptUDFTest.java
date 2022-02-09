package encryptix.hds.hive.udf.encryption.hybrid.fast;

import encryptix.hds.eah.v1.FormatHelper;
import encryptix.hds.hive.exception.InternalInitException;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.WritableStringObjectInspector;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class EAHEncryptUDFTest {

    static EAHEncryptUDF udf;
    static ObjectInspector[] inputObjectInspector = {PrimitiveObjectInspectorFactory.javaStringObjectInspector};
    static WritableStringObjectInspector resultInspector;
    public static final String message = "tes27345yfv8237y4t8f2374yrf82374yrf82g374yrf82374yf5r8g237y4g5ftme";

    @BeforeClass
    static public void initialize() throws InternalInitException, UDFArgumentException {
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_public_key.pem");
        udf = new EAHEncryptUDF();
        resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
    }

    String udfEvaluate(String input) throws HiveException {
        Object evaluationResult = udf.evaluate(new GenericUDF.DeferredObject[]{new GenericUDF.DeferredJavaObject(input)});
        return resultInspector.getPrimitiveJavaObject(evaluationResult);
    }

    @Test
    public void encryptHappyPath() throws HiveException {
        Assert.assertTrue(udfEvaluate(message).startsWith(FormatHelper.FORMAT_SIGNATURE));
    }

    @Test
    public void stabilityTest() throws HiveException {
        int count = 10000;

        for (int i = 0; i < count; i++) {
            Assert.assertTrue(udfEvaluate(message).startsWith(FormatHelper.FORMAT_SIGNATURE));
        }
    }

    @Test
    public void testInitializedIncorrectly() {
        // set wrong key
        System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "wrong_key");

        EAHEncryptUDF udf = new EAHEncryptUDF();

        try {
            // init with wrong key
            resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
            // you shall not pass
            Assert.fail();
        } catch (UDFArgumentException e) {
            // restore property
            System.setProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE, "classpath:eckeys/test/3ccd72b3ba0e42f75994614603736f99_test_public_key.pem");
            // Analyze exception
            Assert.assertTrue(e.getCause() instanceof InternalInitException);
            Assert.assertTrue(e.getCause().getMessage().contains("Failed to find and open public key while initialization"));
        }
    }


}
