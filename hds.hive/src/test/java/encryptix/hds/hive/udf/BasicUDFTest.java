package encryptix.hds.hive.udf;


import encryptix.hds.hive.udf.encryption.hybrid.fast.EAHEncryptUDF;
import org.junit.Assert;
import org.junit.Test;

public class BasicUDFTest {

    @Test
    public void testAgressiveResourceFindPositive() {
        System.setProperty(BasicUDF.PROPERTY_AGGRESSIVE_SEARCH_MODE, "true");

        BasicUDF udf = new EAHEncryptUDF();
        Assert.assertTrue(udf.getResourceFinder().isAggressiveSearchMode());

        System.clearProperty(BasicUDF.PROPERTY_AGGRESSIVE_SEARCH_MODE);
    }

    @Test
    public void testAgressiveResourceFindNegative() {
        System.clearProperty(BasicUDF.PROPERTY_AGGRESSIVE_SEARCH_MODE);

        BasicUDF udf = new EAHEncryptUDF();
        Assert.assertFalse(udf.getResourceFinder().isAggressiveSearchMode());

        System.setProperty(BasicUDF.PROPERTY_AGGRESSIVE_SEARCH_MODE, "random_dksjfg89742");
        udf = new EAHEncryptUDF();
        Assert.assertFalse(udf.getResourceFinder().isAggressiveSearchMode());

        System.clearProperty(BasicUDF.PROPERTY_AGGRESSIVE_SEARCH_MODE);
    }

}
