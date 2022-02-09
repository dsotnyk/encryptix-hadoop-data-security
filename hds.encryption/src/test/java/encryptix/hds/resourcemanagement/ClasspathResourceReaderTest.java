package encryptix.hds.resourcemanagement;

import encryptix.hds.exception.InitializationFailed;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import org.junit.Assert;
import org.junit.Test;

public class ClasspathResourceReaderTest {

    @Test
    public void initDefaultHappyPathTest() throws ResourceNotFound {
        Assert.assertNotNull((new ClasspathResourceReader()).getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"));
    }

    @Test
    public void initCustomHappyPathTest() throws InitializationFailed, ResourceNotFound {
        Assert.assertNotNull((new ClasspathResourceReader(this.getClass().getClassLoader())).getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"));
    }

    @Test(expected = InitializationFailed.class)
    public void initCustomNegativeTest() throws InitializationFailed {
        new ClasspathResourceReader(null);
    }

    @Test
    public void initDefaultSetCustomHappyPathTest() throws InitializationFailed, ResourceNotFound {
        ClasspathResourceReader reader = new ClasspathResourceReader();
        reader.setClassLoader(this.getClass().getClassLoader());
        Assert.assertNotNull(reader.getResource("eckeys/test/47ed2bea86e8f4f9232f0659c1542818_test_private_key_system_encrypted.pem"));
    }

    @Test(expected = InitializationFailed.class)
    public void initDefaultSetCustomNegativeTest() throws InitializationFailed {
        ClasspathResourceReader reader = new ClasspathResourceReader();
        reader.setClassLoader(null);
    }

    @Test(expected = ResourceNotFound.class)
    public void readNonExistingResource() throws ResourceNotFound {
        (new ClasspathResourceReader()).getResource("non_existing.resource");
    }

}
