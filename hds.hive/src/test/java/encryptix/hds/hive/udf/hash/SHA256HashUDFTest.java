package encryptix.hds.hive.udf.hash;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class SHA256HashUDFTest extends BasicTextUDFTest {

    public SHA256HashUDFTest() throws UDFArgumentException, InternalInitException {
        super(new SHA256HashUDF());
    }

    @Test
    public void happyPathTest() throws HiveException {
        Assert.assertEquals("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", udfEvaluate("1"));
        Assert.assertEquals("2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c", udfEvaluate("aaabbb"));
        Assert.assertEquals("dbd03fbd0567232497944bfe3b60d6cd07424f24c733561a2ea7357e542673b5", udfEvaluate("99dc60e12d6ea1b454feb55bbe9a64f3"));
        Assert.assertNotEquals("2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c", udfEvaluate("Aaabbb"));
        Assert.assertNotEquals("dbd03fbd0567232497944bfe3b60d6cd07424f24c733561a2ea7357e542673b5", udfEvaluate("99Dc60e12d6ea1b454feb55bbe9a64f3"));
    }

}
