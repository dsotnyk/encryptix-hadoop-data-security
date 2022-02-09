package encryptix.hds.hive.udf;

import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.WritableStringObjectInspector;

public abstract class BasicTextUDFTest {

    protected BasicTextUDF udf;
    protected ObjectInspector[] inputObjectInspector = {PrimitiveObjectInspectorFactory.javaStringObjectInspector};
    //        JavaStringObjectInspector resultInspector = (JavaStringObjectInspector) udf.initialize(inputObjectInspector);
    protected WritableStringObjectInspector resultInspector;


    public BasicTextUDFTest(BasicTextUDF udf) throws UDFArgumentException {
        this.udf = udf;
        this.resultInspector = (WritableStringObjectInspector) udf.initialize(inputObjectInspector);
    }

    public String udfEvaluate(String input) throws HiveException {
        Object evaluationResult = udf.evaluate(new GenericUDF.DeferredObject[] {new GenericUDF.DeferredJavaObject(input)});
        return resultInspector.getPrimitiveJavaObject(evaluationResult);
    }


}
