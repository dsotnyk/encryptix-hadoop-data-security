package encryptix.hds.hive.property;

import encryptix.hds.resourcemanagement.reader.ClasspathResourceReader;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.common.JavaUtils;
import org.apache.hadoop.hive.ql.exec.MapredContext;
import org.apache.hadoop.hive.ql.session.SessionState;

import java.io.Reader;
import java.util.Properties;

/**
 * Property provider, which is trying to find property with the name given in a different sources
 */
public class MultisourcePropertyReader {

    private static final Log log = LogFactory.getLog(MultisourcePropertyReader.class);

    protected Configuration hadoopConfiguration = null;

    protected MapredContext hiveConfiguration = null;

    protected Properties classpathPropertyFileProperties;

    public enum PROPERTY_SOURCE {
        HIVE_SESSION, HADOOP_CONF, HIVE_CONF, SYSTEM, ENV, CLASSPATH_PROPERTY_FILE
    }

    protected PROPERTY_SOURCE[] sources = PROPERTY_SOURCE.values();

    /**
     * Adds Hive Configuration source
     *
     * @param hiveConfiguration Hive Configuration
     */
    public void addHiveConfigurationSource(MapredContext hiveConfiguration) {
        log.debug("HiveConfiguration was provided");
        this.hiveConfiguration = hiveConfiguration;
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
     * Adds classpath property file
     *
     * @param classpathFileName File name
     * @return Is was found and parsed successfully
     */
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "FindBugs defect on Java7-try-with-resources")
    public boolean addClasspathPropertyFileSource(String classpathFileName) {
        log.debug("ClassPath Property file was provided");

        try (Reader reader = new ClasspathResourceReader(JavaUtils.getClassLoader()).getResource(classpathFileName)) {
            Properties properties = new Properties();
            properties.load(reader);
            // still alive? wow!
            this.classpathPropertyFileProperties = properties;
            return true;
        } catch (Exception e) {
            log.error("Failed to read ClassPath Property file "+ classpathFileName, e);
            return false;
        }
    }


    public MultisourcePropertyReader switchSources(PROPERTY_SOURCE... sources) {
        this.sources = sources;
        return this;
    }

    public static String readSystemProperty(String propertyName) {
        return System.getProperty(propertyName);
    }

    public static String readEnvironmentProperty(String propertyName) {
        return System.getenv(propertyName);
    }

    /**
     * Finds value in Hadoop Configuration
     *
     * @param propertyName property name to find
     * @return Value or null, if not found or configuration is not initialized
     */
    public String readHadoopConfigurationProperty(String propertyName) {
        if (hadoopConfiguration == null) {
            log.debug("HadoopConfiguration is null when trying to find property " + propertyName + ", falling back to null");
            return null;
        } else return hadoopConfiguration.get(propertyName);
    }

    /**
     * Finds value in Hive Configuration
     *
     * @param propertyName property name to find
     * @return Value or null, if not found or configuration is not initialized
     */
    public String readHiveConfigurationProperty(String propertyName) {
        if (hiveConfiguration == null || hiveConfiguration.getJobConf() == null) {
            log.debug("HiveConfiguration is null when trying to find property " + propertyName + ", falling back to null");
            return null;
        } else return hiveConfiguration.getJobConf().get(propertyName);
    }

    /**
     * Finds value in Hive Session
     *
     * @param propertyName property name to find
     * @return Value or null, if not found or session is not initialized
     */
    // Yep, it's static also, 'cause SessionState is built on the top of ThreadLocal
    public static String readHiveSessionProperty(String propertyName) {
        SessionState hiveSessionState = SessionState.get();

        if (hiveSessionState == null) {
            log.debug("SessionState is null when trying to find property " + propertyName + ", falling back to null");
            return null;
        } else return hiveSessionState.getHiveVariables().get(propertyName);
    }

    /**
     * Try to find properties in a sources listed in given order
     *
     * @param propertyName Property name to find
     * @return property value or null if nothing found
     */
    public String findProperty(String propertyName) {
        return findProperty(propertyName, null);
    }


    /**
     * Try to find properties in a sources listed in given order
     *
     * @param propertyName Property name to find
     * @param defaultValue Default value, to be returned if property not found or can't be read instead of null
     * @return property value or default value or null if nothing found
     */
    @SuppressWarnings({"PMD.EmptyCatchBlock", "PMD.UselessParentheses"})
    public String findProperty(String propertyName, String defaultValue) {

        String value = null;

        // for every source
        for (PROPERTY_SOURCE propertySource : this.sources) {
            try {
                value = readPropertyFromSource(propertyName, propertySource);

                if (value == null) {
                    log.info("For property " + propertyName + " value was NOT found in the source " + propertySource.name());
                } else {
                    log.info("For property " + propertyName + " found value " + value + " in the source " + propertySource.name());
                    break;
                }
            } catch (Exception e) {
                log.error("Error occurred while reading property " + propertyName + " from the source " + propertySource.name(), e);
            }
        }

        log.debug("Finished search for property " + propertyName + ", value found is " + value);
        return (value == null && defaultValue != null) ? defaultValue : value;
    }

    /**
     * Read property from the property file from classpath
     *
     * @param propertyName Property name to read
     * @return Value or null if property file source wasn't set or property is not found
     */
    public String readClassPathPropertyFile(String propertyName) {
        if (classpathPropertyFileProperties == null) {
            log.debug("ClassPath File Properties is null when trying to find property " + propertyName + ", falling back to null");
            return null;
        } else return classpathPropertyFileProperties.getProperty(propertyName);
    }

    /**
     * Reads property from the source specified
     *
     * @param propertyName   Property name
     * @param propertySource Source to read
     * @return Property value
     */
    protected String readPropertyFromSource(String propertyName, PROPERTY_SOURCE propertySource) {
        String value;
        switch (propertySource) {
            case ENV:
                value = readEnvironmentProperty(propertyName);
                break;
            case SYSTEM:
                value = readSystemProperty(propertyName);
                break;
            case HADOOP_CONF:
                value = readHadoopConfigurationProperty(propertyName);
                break;
            case HIVE_CONF:
                value = readHiveConfigurationProperty(propertyName);
                break;
            case HIVE_SESSION:
                value = readHiveSessionProperty(propertyName);
                break;
            case CLASSPATH_PROPERTY_FILE:
                value = readClassPathPropertyFile(propertyName);
                break;
            default:
                throw new IllegalArgumentException("Source " + propertySource + " is not supported");
        }
        return value;
    }

}
