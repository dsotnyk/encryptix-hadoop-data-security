package encryptix.hds.hive.udf;

import encryptix.hds.hive.udf.utils.UDFArgumentUtils;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDFUtils;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.PrimitiveObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorConverter;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;

/**
 * Base UDF for plain text processing
 */
public abstract class BasicTextUDF extends BasicUDF {

    protected transient PrimitiveObjectInspectorConverter.StringConverter stringConverter;
    protected transient GenericUDFUtils.StringHelper stringHelper;

    public BasicTextUDF(String udfFunctionName) {
        super(udfFunctionName);
    }

    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {

        // check arguments count
        if (arguments.length != 1) {
            throw new UDFArgumentException("Function takes only one argument");
        }

        // check argument category and type
        if (!UDFArgumentUtils.isPrimitiveCategory(arguments[0], PrimitiveObjectInspector.PrimitiveCategory.STRING)) {
            throw new UDFArgumentException("Function takes only string as parameter");
        }

        // init helpers
        this.stringConverter = new PrimitiveObjectInspectorConverter.StringConverter((PrimitiveObjectInspector) arguments[0]);
        this.stringHelper = new GenericUDFUtils.StringHelper(PrimitiveObjectInspector.PrimitiveCategory.STRING);

        // send return type
        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
        // TODO Check functional and non-functional results of alternative approach
        // return PrimitiveObjectInspectorFactory.javaStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException {

        if (arguments[0] == null || arguments[0].get() == null) {
            return null;
        }

        String value = (String) this.stringConverter.convert(arguments[0].get());

        return this.stringHelper.setReturnValue(processValue(value));

    }

    protected abstract String processValue(String value);
}
