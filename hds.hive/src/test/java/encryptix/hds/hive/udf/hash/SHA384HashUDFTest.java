package encryptix.hds.hive.udf.hash;

import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class SHA384HashUDFTest extends BasicTextUDFTest {

    public SHA384HashUDFTest() throws UDFArgumentException, InternalInitException {
        super(new SHA384HashUDF());
    }

    @Test
    public void happyPathTest() throws HiveException {
        Assert.assertEquals("47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776", udfEvaluate("1"));
        Assert.assertEquals("93a8ded6ed9ec617e1dbd7b552c0f87b7fee64728297666cc55cc26f08dc2d4d9dbeb22a845abe7101333b5d7f1b57ef", udfEvaluate("aaabbb"));
        Assert.assertEquals("0ab23224899cf846c4d2c36433a7b550666ac383b391b99c69af2a7a18979dfdcd73a3160f2121ed91f436dfa788a7c2", udfEvaluate("99dc60e12d6ea1b454feb55bbe9a64f3"));
        Assert.assertNotEquals("93a8ded6ed9ec617e1dbd7b552c0f87b7fee64728297666cc55cc26f08dc2d4d9dbeb22a845abe7101333b5d7f1b57ef", udfEvaluate("Aaabbb"));
        Assert.assertNotEquals("0ab23224899cf846c4d2c36433a7b550666ac383b391b99c69af2a7a18979dfdcd73a3160f2121ed91f436dfa788a7c2", udfEvaluate("99Dc60e12d6ea1b454feb55bbe9a64f3"));
    }

}
