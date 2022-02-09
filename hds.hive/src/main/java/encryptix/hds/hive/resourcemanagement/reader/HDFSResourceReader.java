
package encryptix.hds.hive.resourcemanagement.reader;

import encryptix.hds.exception.InitializationFailed;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;
import encryptix.hds.resourcemanagement.reader.ResourceReader;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hive.ql.session.SessionState;
import org.apache.hadoop.mapred.JobConf;

import java.io.*;
import java.net.URL;

/**
 * HDFS resource reader
 */
public class HDFSResourceReader extends ResourceReader {

    public static final String HADOOP_CONF_DIR_PROPERTY_NAME = "HADOOP_CONF_DIR";

    /**
     * Hadoop configuration, if arrived due to initialization of MR job
     */
    protected Configuration hadoopConfiguration = null;

    /**
     * Hive Job Configuration, if arrived due to UDF initialization
     */
    protected Configuration hiveJobConfiguration = null;

    private static final Log log = LogFactory.getLog(HDFSResourceReader.class);

    /**
     * Should we fallback to read Hadoop configuration from directory, specified in HADOOP_CONF_DIR Java property
     */
    protected boolean fallbackReadHadoopFilesFromFS = false;

    /**
     * Adds Hive Job Configuration
     *
     * @param hiveJobConfiguration Hive Job Configuration
     */
    public void addHiveJobConfiguration(JobConf hiveJobConfiguration) {
        log.debug("HiveConfiguration was provided");
        this.hiveJobConfiguration = hiveJobConfiguration;
    }

    /**
     * Adds Hadoop Configuration source
     *
     * @param hadoopConfiguration Hadoop Configuration
     */
    public void addHadoopConfigurationSource(Configuration hadoopConfiguration) {
        log.debug("HadoopConfiguration was provided");
        this.hadoopConfiguration = hadoopConfiguration;
    }

    /**
     * On fallback, should code to try to read configuration files of Hadoop from FS
     *
     * @param fallbackReadHadoopFilesFromFS should code to try to read configuration files of Hadoop from FS
     */
    public void setFallbackReadHadoopFilesFromFS(boolean fallbackReadHadoopFilesFromFS) {
        this.fallbackReadHadoopFilesFromFS = fallbackReadHadoopFilesFromFS;
    }

    @Override
    public Reader getResource(String resourcePath) throws ResourceNotFound, InitializationFailed, ResourceReadFailed {

        FileSystem fileSystem;
        try {
            fileSystem = FileSystem.get(findConfiguration());
        } catch (IOException e) {
            log.error("Can't init HDFS filesystem", e);
            throw new InitializationFailed("Can't init HDFS filesystem", e);
        }

        FSDataInputStream dataInputStream;
        try {
            dataInputStream = fileSystem.open(new Path(resourcePath));
        } catch (IOException e) {
            log.error("Failed to read " + resourcePath + " from HDFS", e);
            throw new ResourceReadFailed("Failed to read " + resourcePath + " from HDFS", e);
        }

        return new BufferedReader(new InputStreamReader(dataInputStream, conversionCharset));
    }

    /**
     * Find proper Hadoop configuration to access HDFS
     *
     * Tries to find HiveJob Configuration, then Hive Session, then Hadoop Configuration, then will create default
     * configuration and fill it with classpath configuration files.
     *
     * If fallback read allowed (see HDFSResourceReader.setFallbackReadHadoopFilesFromFS()) - will try to read conf dir
     * in addition to configuration files
     *
     * @return Configuration
     *
     */
    protected Configuration findConfiguration() {
        if (hiveJobConfiguration != null) {
            log.debug("Starting with hiveJobConfiguration");
            return hiveJobConfiguration;
        }

        if (SessionState.get() != null && SessionState.get().getConf() != null) {
            log.debug("Starting with SessionState configuration");
            return SessionState.get().getConf();
        }

        if (hadoopConfiguration != null) {
            log.debug("Starting with hadoopConfiguration");
            return hadoopConfiguration;
        }

        log.debug("No existing configuration found, falling back to manually initialized");
        return createNewConfiguration();
    }

    /**
     * Creates default configuration and fill it with classpath configuration files.
     *
     * If fallback read allowed (see HDFSResourceReader.setFallbackReadHadoopFilesFromFS()) - will try to read conf dir
     * in addition to configuration files
     *
     * @return default pre-initialized Confguration
     */
    protected Configuration createNewConfiguration() {

        // load defaults, "core-default.xml" and "core-site.xml"
        Configuration configuration = new Configuration();

        // load expected configuration, mapred-site.xml, mapred-default.xml, hdfs-site.xml hdfs-default.xml
        configuration.addResource("mapred-default.xml");
        configuration.addResource("mapred-site.xml");

        configuration.addResource("hdfs-default.xml");
        configuration.addResource("hdfs-site.xml");

        // load Hadoop configuration from FS if any and if requested
        if (fallbackReadHadoopFilesFromFS) {
            log.debug("Configured manual read of Hadoop configuration from FS");
            try {
                mergeFSHadoopConfiguration(configuration);
            } catch (RuntimeException re) {
                log.error("Reading of Hadoop configuration from FS failed", re);
            }
        }

        return configuration;
    }

    /**
     * Reads and adds Hadoop configuration from directory, specified in HADOOP_CONF_DIR Java property
     *
     * @param configuration Configuration to update
     */
/*
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
            value = {"REC_CATCH_EXCEPTION", "SIC_INNER_SHOULD_BE_STATIC_ANON"},
            justification = "Findbugs bug, missed IOException from file.getCanonicalPath(); Don't like idea with static anon class"
    )
*/
    protected void mergeFSHadoopConfiguration(Configuration configuration) {

        log.debug("Started mergeFSHadoopConfiguration to load configuration from FS");

        String hadoopConfPath = System.getProperty(HADOOP_CONF_DIR_PROPERTY_NAME);

        if (StringUtils.isEmpty(hadoopConfPath)) {
            log.error("HADOOP_CONF_DIR is not set, skipping FS load in mergeFSHadoopConfiguration");
            return;
        } else {
            log.debug("Found configuration dir, it points to " + hadoopConfPath);
        }

        File dir = new File(hadoopConfPath);

        if (!dir.exists() || !dir.isDirectory()) {
            log.error("HADOOP_CONF_DIR points to invalid place " + hadoopConfPath);
            return;
        }

        File[] files = dir.listFiles(
                new FilenameFilter() {
                    public boolean accept(File dir, String name) {
                        return name.endsWith("xml");
                    }
                }
        );

        if (files == null) {
            log.error("Configuration dir does not denote a directory, or if an I/O error occured. Dir used " + hadoopConfPath);
            return;
        }

        for (File file : files) {
            try {
                URL url = new URL("file://" + file.getCanonicalPath());
                configuration.addResource(url);
            } catch (Exception e) {
                log.error("Failed to open configuration file " + file.getPath(), e);
            }
        }

    }
}
