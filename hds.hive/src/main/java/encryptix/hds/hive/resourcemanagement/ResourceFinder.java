package encryptix.hds.hive.resourcemanagement;


import encryptix.hds.exception.InitializationFailed;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;
import encryptix.hds.hive.resourcemanagement.reader.HDFSResourceReader;
import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.common.JavaUtils;
import org.apache.hadoop.mapred.JobConf;

import java.io.Reader;
import java.io.StringReader;
import java.util.Map;

/**
 * Class for finding the resource from the list
 * <p/>
 * Well, we have pretty strange situation with ClassLoaders in Hive.
 * <p/>
 * Developers of the core Hive use construction like
 * https://svn.apache.org/repos/asf/hive/trunk/common/src/java/org/apache/hadoop/hive/conf/HiveConf.java
 * <p/>
 * ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
 * if (classLoader == null) {
 * classLoader = HiveConf.class.getClassLoader();
 * }
 * <p/>
 * In the same time, Hive Core includes JavaUtils.getClassLoader() which is marked as
 * "Standard way of getting classloader in Hive code (outside of Hadoop). Uses the context loader to get access
 * to classpaths to auxiliary and jars added with 'add jar' command. Falls back to current classloader.
 * In Hadoop-related code, we use Configuration.getClassLoader()."
 * <p/>
 * And implementation is pretty similar
 * <p/>
 * ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
 * if(classLoader == null) {
 * classLoader = JavaUtils.class.getClassLoader();
 * }
 * <p/>
 * Also some UDF trying to load resources like this.getClass().getResource which is understandable
 */
public class ResourceFinder {

    protected Configuration hadoopConfiguration = null;

    protected JobConf hiveJobConfiguration = null;

    private static final Log log = LogFactory.getLog(ResourceFinder.class);

    private boolean aggressiveSearchMode = false;


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
     * Get resource from the list
     *
     * @param resources Resources to read, resource path format
     * @return Reader or null, if nothing found or can be opened
     */
    public Reader getResource(String resources) {
        return getResource(ResourcePathFormatParser.parseSources(resources));
    }

    /**
     * Force resource finder to use all available ways to find and open resources, including various bypasses
     *
     * For example, HDFSResourceReader in this mode will try to find Hadoop configuration folder on FS and read
     * configuration files on it's own to access hdfs resources.
     *
     * @see HDFSResourceReader
     *
     * @param aggressiveSearchMode Should resource finder use all available ways to find and open resources, including various bypasses
     */
    public void setAggressiveSearchMode(boolean aggressiveSearchMode) {
        this.aggressiveSearchMode = aggressiveSearchMode;
    }

    public boolean isAggressiveSearchMode() {
        return aggressiveSearchMode;
    }

    /**
     * Get resource from the list
     *
     * @param resources Resources to read, map of types and resources names
     * @return Reader or null, if nothing found or can be opened
     */
    @SuppressWarnings("PMD.EmptyCatchBlock")
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "DM_CONVERT_CASE", justification = "Default used")
    public Reader getResource(Map<String, String> resources) {

        Reader reader = null;

        for (Map.Entry<String, String> resourceEntry : resources.entrySet()) {

            String sourceType = resourceEntry.getKey();
            String sourceValue = resourceEntry.getValue();

            log.debug("Processing entry " + sourceType + ":" + sourceValue);

            try {
                // TODO: Implement FS
                switch (sourceType.toUpperCase()) {
                    case "CLASSPATH":
                        // Use ClassLoader from Hive
                        reader = new ClasspathResourceReader(JavaUtils.getClassLoader()).getResource(sourceValue);
                        break;
                    case "TEXT":
                        reader = new StringReader(sourceValue);
                        break;
                    case "HDFS":

                        HDFSResourceReader hdfsResourceReader = new HDFSResourceReader();
                        hdfsResourceReader.addHadoopConfigurationSource(this.hadoopConfiguration);
                        hdfsResourceReader.addHiveJobConfiguration(this.hiveJobConfiguration);
                        hdfsResourceReader.setFallbackReadHadoopFilesFromFS(aggressiveSearchMode);

                        reader = hdfsResourceReader.getResource(sourceValue);
                        break;
                    default: log.error("Source entry type "+resourceEntry.getKey().toUpperCase()+" is not known!");
                }
            } catch (ResourceNotFound e) {
                log.error("Source entry "+sourceType+":"+sourceValue+", resource is not found!", e);
            } catch (InitializationFailed initializationFailed) {
                log.error("Source entry "+sourceType+":"+sourceValue+", init failed", initializationFailed);
            } catch (ResourceReadFailed resourceReadFailed) {
                log.error("Source entry "+sourceType+":"+sourceValue+", read failed", resourceReadFailed);
            }

            // found reader - cancel search
            if (reader != null) {
                log.debug("Source entry "+sourceType+":"+sourceValue+", no reader found");
                return reader;
            }
        }

        return null;
    }


}
