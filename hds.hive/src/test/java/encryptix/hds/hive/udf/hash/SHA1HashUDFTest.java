package encryptix.hds.hive.udf.hash;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class SHA1HashUDFTest extends BasicTextUDFTest {

    public SHA1HashUDFTest() throws UDFArgumentException, InternalInitException {
        super(new SHA1HashUDF());
    }

    @Test
    public void happyPathTest() throws HiveException {
        Assert.assertEquals("356a192b7913b04c54574d18c28d46e6395428ab", udfEvaluate("1"));
        Assert.assertEquals("68d8572c2662b0f06f723d7d507954fb038b8558", udfEvaluate("aaabbb"));
        Assert.assertEquals("604fb2c89721ae0ac015983d9266f3c4459c89db", udfEvaluate("99dc60e12d6ea1b454feb55bbe9a64f3"));
        Assert.assertNotEquals("68d8572c2662b0f06f723d7d507954fb038b8558", udfEvaluate("Aaabbb"));
        Assert.assertNotEquals("604fb2c89721ae0ac015983d9266f3c4459c89db", udfEvaluate("99Dc60e12d6ea1b454feb55bbe9a64f3"));
    }

}
