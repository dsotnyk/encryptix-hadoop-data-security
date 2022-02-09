package encryptix.hds.hive.udf.hash;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class SHA512HashUDFTest extends BasicTextUDFTest {

    public SHA512HashUDFTest() throws UDFArgumentException, InternalInitException {
        super(new SHA512HashUDF());
    }

    @Test
    public void happyPathTest() throws HiveException {
        Assert.assertEquals("4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a", udfEvaluate("1"));
        Assert.assertEquals("afdb9638e99117fd7477f3d2d578c6a37a6853945c64e88a81cc8734604cd5afd4fea8c82b1159d943bf1bfc68f6bbcfecd04f61cf5271500f125bd4f756c2ba", udfEvaluate("aaabbb"));
        Assert.assertEquals("a60d6fc9e1193d2974c71a762fb4d9cdb84246564b70cfc4467fb638bd6b33d1b57a3591a503e6769bea24138be3c4b06d3cd2775bd680919b72225aaed92438", udfEvaluate("99dc60e12d6ea1b454feb55bbe9a64f3"));
        Assert.assertNotEquals("afdb9638e99117fd7477f3d2d578c6a37a6853945c64e88a81cc8734604cd5afd4fea8c82b1159d943bf1bfc68f6bbcfecd04f61cf5271500f125bd4f756c2ba", udfEvaluate("Aaabbb"));
        Assert.assertNotEquals("a60d6fc9e1193d2974c71a762fb4d9cdb84246564b70cfc4467fb638bd6b33d1b57a3591a503e6769bea24138be3c4b06d3cd2775bd680919b72225aaed92438", udfEvaluate("99Dc60e12d6ea1b454feb55bbe9a64f3"));
    }

}
