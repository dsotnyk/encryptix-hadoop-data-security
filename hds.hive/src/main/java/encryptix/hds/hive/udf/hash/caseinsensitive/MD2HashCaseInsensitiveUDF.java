package encryptix.hds.hive.udf.hash.caseinsensitive;

import encryptix.hds.hash.DigestAlgorithm;
import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.hash.BasicHashUDF;
import org.apache.hadoop.hive.ql.exec.Description;

// TODO : Javadoc
// TODO : VectorExpression
/* TODO : Add support of VARCHAR and CHAR.
 * See https://cwiki.apache.org/confluence/display/Hive/LanguageManual+Types#LanguageManualTypes-StringTypes
 * See GenericUDFBaseTrim
 */
@Description(
        name = "md2sum_ci",
        value = "_FUNC_(x) - returns the hash of the value",
        extended = "Example:\n  > SELECT _FUNC_('value') FROM src LIMIT 1;\n  4dff4ea340f0a823f15d3f4f01ab62eae0e5da..."
)
public class MD2HashCaseInsensitiveUDF extends BasicHashUDF {

    public MD2HashCaseInsensitiveUDF() throws InternalInitException {
        super("md2sum", DigestAlgorithm.MD2, true);
    }
}
