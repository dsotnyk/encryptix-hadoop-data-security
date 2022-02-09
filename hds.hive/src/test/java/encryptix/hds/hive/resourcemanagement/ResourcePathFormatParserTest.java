package encryptix.hds.hive.resourcemanagement;

import org.junit.Assert;
import org.junit.Test;

import java.util.Iterator;
import java.util.Map;

public class ResourcePathFormatParserTest {

    @Test
    public void testParseSourcesHappyPath() {

        Map<String,String> sources = ResourcePathFormatParser.parseSources("type1:value1, type2 : value2    ,  ,,,,,   ,,   ,,:,, type3 :    value3  : value3  addon     : and ::: addon   , :  ignored value, :,: ,:,       :");

        // check values
        Assert.assertTrue(sources.size() == 3);
        Assert.assertTrue(sources.get("type1").equals("value1"));
        Assert.assertTrue(sources.get("type2").equals("value2"));
        Assert.assertTrue(sources.get("type3").equals("value3  : value3  addon     : and ::: addon"));

        // check order
        Iterator<String> keysIterator = sources.keySet().iterator();
        Assert.assertTrue(keysIterator.next().equals("type1"));
        Assert.assertTrue(keysIterator.next().equals("type2"));
        Assert.assertTrue(keysIterator.next().equals("type3"));
    }
}
