package encryptix.hds.hive.resourcemanagement.reader;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.ql.session.SessionState;
import org.apache.hadoop.mapred.JobConf;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class HDFSResourceReaderTest {

    private Path initSystemHadoopConfDir() throws IOException {
        // prepare test dir
        Path tempPath = Files.createTempDirectory(null);

        // init system variable
        System.setProperty(HDFSResourceReader.HADOOP_CONF_DIR_PROPERTY_NAME, tempPath.toString());

        return Files.createTempFile(tempPath, null, ".xml");
    }

    @Test
    public void testAddFSHadoopConfigurationReadWithFallback() throws IOException, NoSuchFieldException {

        Path tempConfFile = initSystemHadoopConfDir();

        // init and set fallback
        HDFSResourceReader hdfsResourceReader = new HDFSResourceReader();
        hdfsResourceReader.setFallbackReadHadoopFilesFromFS(true);

        // Find configuration
        Configuration configuration = hdfsResourceReader.findConfiguration();

        String resourcesDump = configuration.toString();

        assertDefaultRersources(resourcesDump, true);
        assertAdditionalMapRedResources(resourcesDump, true);
        assertAdditionalHDFSResources(resourcesDump, true);
        assertFallbackResources(resourcesDump, tempConfFile, true);

    }

    @Test
    public void testAddFSHadoopConfigurationReadWithoutFallback() throws IOException, NoSuchFieldException {

        Path tempConfFile = initSystemHadoopConfDir();

        // init and set fallback
        HDFSResourceReader hdfsResourceReader = new HDFSResourceReader();
        hdfsResourceReader.setFallbackReadHadoopFilesFromFS(false);

        // Init configuration
        Configuration configuration = hdfsResourceReader.findConfiguration();

        String resourcesDump = configuration.toString();

        assertDefaultRersources(resourcesDump, true);
        assertAdditionalMapRedResources(resourcesDump, true);
        assertAdditionalHDFSResources(resourcesDump, true);
        assertFallbackResources(resourcesDump, tempConfFile, false);
    }

    protected void assertFallbackResources(String resourcesDump, Path tempConfFile, boolean contains) {
        Assert.assertEquals(resourcesDump.contains(tempConfFile.getFileName().toString()), contains);
    }

    protected void assertAdditionalMapRedResources(String resourcesDump, boolean contains) {
        Assert.assertEquals(resourcesDump.contains("mapred-site.xml"), contains);
        Assert.assertEquals(resourcesDump.contains("mapred-default.xml"), contains);
    }

    protected void assertAdditionalHDFSResources(String resourcesDump, boolean contains) {
        Assert.assertEquals(resourcesDump.contains("hdfs-site.xml"), contains);
        Assert.assertEquals(resourcesDump.contains("hdfs-default.xml"), contains);
    }


    protected void assertDefaultRersources(String resourcesDump, boolean contains) {
        Assert.assertEquals(resourcesDump.contains("core-default.xml"), contains);
        Assert.assertEquals(resourcesDump.contains("core-site.xml"), contains);
    }

    @Test
    public void testInitOrder() throws IOException, NoSuchFieldException {

        Path tempConfFile = initSystemHadoopConfDir();

        // init and set fallback
        HDFSResourceReader hdfsResourceReader = new HDFSResourceReader();
        hdfsResourceReader.setFallbackReadHadoopFilesFromFS(true);

        // ------------ Fallback added -------------------------
        // Init configuration
        Configuration configuration = hdfsResourceReader.findConfiguration();

        String resourcesDump = configuration.toString();

        assertDefaultRersources(resourcesDump, true);
        assertAdditionalMapRedResources(resourcesDump, true);
        assertAdditionalHDFSResources(resourcesDump, true);
        assertFallbackResources(resourcesDump, tempConfFile, true);

        // ----------- Hadoop Conf added ----------------------
        Configuration hadoopConfiguration = new Configuration();
        hadoopConfiguration.addResource("hadoop_test_configuration.xml");
        hdfsResourceReader.addHadoopConfigurationSource(hadoopConfiguration);

        configuration = hdfsResourceReader.findConfiguration();
        resourcesDump = configuration.toString();

        assertDefaultRersources(resourcesDump, true);
        assertAdditionalMapRedResources(resourcesDump, false);
        assertAdditionalHDFSResources(resourcesDump, false);
        assertFallbackResources(resourcesDump, tempConfFile, false);
        Assert.assertTrue(resourcesDump.contains("hadoop_test_configuration.xml"));

        // ----------- Hive Job Conf added ----------------------
        HiveConf hiveConf = new HiveConf();
        hiveConf.addResource("hive_test_configuration.xml");
        SessionState.setCurrentSessionState(new SessionState(hiveConf));

        configuration = hdfsResourceReader.findConfiguration();
        resourcesDump = configuration.toString();

        assertDefaultRersources(resourcesDump, true);
        assertAdditionalMapRedResources(resourcesDump, true); // included automatically to HiveConf
        assertAdditionalHDFSResources(resourcesDump, false);
        assertFallbackResources(resourcesDump, tempConfFile, false);
        Assert.assertFalse(resourcesDump.contains("hadoop_test_configuration.xml"));
        Assert.assertTrue(resourcesDump.contains("hive_test_configuration.xml"));

        // ----------- Hive UDF configuration added ----------------------
        JobConf udfConfiguration = new JobConf();
        udfConfiguration.addResource("udf_test_configuration.xml");
        hdfsResourceReader.addHiveJobConfiguration(udfConfiguration);

        configuration = hdfsResourceReader.findConfiguration();
        resourcesDump = configuration.toString();

        assertDefaultRersources(resourcesDump, true);
        assertAdditionalMapRedResources(resourcesDump, true); // included automatically to JobConf
        assertAdditionalHDFSResources(resourcesDump, false);
        assertFallbackResources(resourcesDump, tempConfFile, false);
        Assert.assertFalse(resourcesDump.contains("hadoop_test_configuration.xml"));
        Assert.assertFalse(resourcesDump.contains("hive_test_configuration.xml"));
        Assert.assertTrue(resourcesDump.contains("udf_test_configuration.xml"));

        SessionState.detachSession();
    }


}
