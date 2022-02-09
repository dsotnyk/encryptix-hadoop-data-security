package encryptix.hds.hive.udf.encryption;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.encryption.hybrid.fast.EAHDecryptUDF;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.WritableStringObjectInspector;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ConfigurationCheckUDFTest {

    static ConfigurationCheckUDF udf;
    static WritableStringObjectInspector resultInspector;

    @BeforeClass
    static public void initialize() throws InternalInitException, UDFArgumentException {
        udf = new ConfigurationCheckUDF();
        resultInspector = (WritableStringObjectInspector) udf.initialize(null);
    }

    String udfEvaluate() throws HiveException {
        Object evaluationResult = udf.evaluate(null);
        return resultInspector.getPrimitiveJavaObject(evaluationResult);
    }

    @Test
    public void configurationHappyPath() throws HiveException {
        String output = udfEvaluate();
        Assert.assertTrue(output.contains(EAHDecryptUDF.PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED));
    }

}
