package encryptix.hds.hive.udf.hash.caseinsensitive;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class MD5HashCaseInsensitiveUDFTest extends BasicTextUDFTest {

    public MD5HashCaseInsensitiveUDFTest() throws UDFArgumentException, InternalInitException {
        super(new MD5HashCaseInsensitiveUDF());
    }

    @Test
    public void happyPathTest() throws HiveException {
        Assert.assertEquals("c4ca4238a0b923820dcc509a6f75849b", udfEvaluate("1"));
        Assert.assertEquals("6547436690a26a399603a7096e876a2d", udfEvaluate("aaabbb"));
        Assert.assertEquals("ce148c91996f8645bdb4325fb57918f8", udfEvaluate("99dc60e12d6ea1b454feb55bbe9a64f3"));
        Assert.assertEquals("6547436690a26a399603a7096e876a2d", udfEvaluate("Aaabbb"));
        Assert.assertEquals("ce148c91996f8645bdb4325fb57918f8", udfEvaluate("99Dc60e12d6ea1b454feb55bbe9a64f3"));
    }

}
