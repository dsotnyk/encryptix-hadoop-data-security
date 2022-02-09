package encryptix.hds.hive.property;

import org.junit.Assert;
import org.junit.Test;

public class MultisourcePropertyReaderTest {

    @Test
    public void testEnvironmentHappyPath() {
        Assert.assertNotNull(MultisourcePropertyReader.readEnvironmentProperty("PATH"));
    }

    @Test
    public void testEnvironmentNegative() {
        Assert.assertNull(MultisourcePropertyReader.readEnvironmentProperty("RRRRRAAAAAAANDOOOM145761982745691v8b91284567v"));
    }

    @Test
    public void testSystemHappyPath() {
        Assert.assertNotNull(MultisourcePropertyReader.readSystemProperty("java.version"));
    }

    @Test
    public void testSystemNegative() {
        Assert.assertNull(MultisourcePropertyReader.readSystemProperty("RRRRRAAAAAAANDOOOM145761982745691v8b91284567v"));
    }

    @Test
    public void testFindHappyPath() {
        MultisourcePropertyReader propertyReader = new MultisourcePropertyReader();
        Assert.assertNotNull(propertyReader.findProperty("PATH"));
        Assert.assertNotNull(propertyReader.findProperty("java.version"));
        Assert.assertNotNull(propertyReader.switchSources(MultisourcePropertyReader.PROPERTY_SOURCE.ENV).findProperty("PATH"));
        Assert.assertNotNull(propertyReader.switchSources(MultisourcePropertyReader.PROPERTY_SOURCE.SYSTEM).findProperty("java.version"));
    }

    @Test
    public void testFindNegative() {
        MultisourcePropertyReader propertyReader = new MultisourcePropertyReader();
        Assert.assertNull(propertyReader.switchSources(MultisourcePropertyReader.PROPERTY_SOURCE.SYSTEM).findProperty("PATH"));
        Assert.assertNull(propertyReader.switchSources(MultisourcePropertyReader.PROPERTY_SOURCE.ENV).findProperty("java.version"));
    }

    @Test
    public void testFileReadHappyPath() {
        MultisourcePropertyReader propertyReader = new MultisourcePropertyReader();
        propertyReader.addClasspathPropertyFileSource("test.properties");

        Assert.assertEquals(
                "value1",
                propertyReader.readClassPathPropertyFile("property1")
        );

        Assert.assertEquals(
                "value2",
                propertyReader.readClassPathPropertyFile("property2")
        );

        Assert.assertEquals(
                "value3",
                propertyReader.readClassPathPropertyFile("property3")
        );


        Assert.assertNull(propertyReader.readClassPathPropertyFile("property4"));
        Assert.assertNull(propertyReader.switchSources(MultisourcePropertyReader.PROPERTY_SOURCE.ENV).findProperty("java.version"));
    }

    @Test
    public void testFileReadNotFound() {
        MultisourcePropertyReader propertyReader = new MultisourcePropertyReader();

        Assert.assertFalse(propertyReader.addClasspathPropertyFileSource("nodfound.properties"));

        Assert.assertNull(propertyReader.readClassPathPropertyFile("property1"));
    }


}
