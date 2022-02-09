package encryptix.hds.hive.udf.hash.caseinsensitive;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class MD2HashCaseInsensitiveUDFTest extends BasicTextUDFTest {

    public MD2HashCaseInsensitiveUDFTest() throws UDFArgumentException, InternalInitException {
        super(new MD2HashCaseInsensitiveUDF());
    }

    @Test
    public void happyPathTest() throws HiveException {
        Assert.assertEquals("c92c0babdc764d8674bcea14a55d867d", udfEvaluate("1"));
        Assert.assertEquals("3c8345b995e1b9bf8bfa4ad97596658b", udfEvaluate("aaabbb"));
        Assert.assertEquals("09b5f457e3b1cf8ca5a321b5df1b003a", udfEvaluate("99dc60e12d6ea1b454feb55bbe9a64f3"));
        Assert.assertEquals("3c8345b995e1b9bf8bfa4ad97596658b", udfEvaluate("Aaabbb"));
        Assert.assertEquals("09b5f457e3b1cf8ca5a321b5df1b003a", udfEvaluate("99Dc60e12d6ea1b454feb55bbe9a64f3"));
    }

}
