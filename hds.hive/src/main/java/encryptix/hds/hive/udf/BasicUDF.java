package encryptix.hds.hive.udf;

import encryptix.hds.hive.property.MultisourcePropertyReader;
import encryptix.hds.hive.resourcemanagement.ResourceFinder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.ql.exec.MapredContext;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;

public abstract class BasicUDF extends GenericUDF implements Configurable {

    private static final Log log = LogFactory.getLog(BasicUDF.class);

    public static final String DEFAULT_CLASSPATH_PROPERTIES_FILE = "hds.hive.udf.properties";

    public static final String PROPERTY_AGGRESSIVE_SEARCH_MODE = "eah.resource.search.aggressive";

    /**
     * Invocation context
     */
    private MapredContext mapReduceContext = null;

    /**
     * Hadoop Configuration
     */
    private Configuration hadoopConfiguration = null;

    private MultisourcePropertyReader propertyReader;

    private ResourceFinder resourceFinder;

    /**
     Save MR context, if arrived
      */
    @Override
    public void configure(MapredContext context) {
        if (context != null) {
            this.mapReduceContext = context;
            this.propertyReader.addHiveConfigurationSource(context);
            this.resourceFinder.addHiveJobConfiguration(context.getJobConf());
            log.debug("Non-empty MapredContext arrived");
        } else {
            log.error("Empty MapredContext arrived");
        }
    }

    /**
     * Save Hadoop configuration, if arrived
      */
    @Override
    public void setConf(Configuration conf) {
        if (conf != null) {
            this.hadoopConfiguration = conf;
            this.propertyReader.addHadoopConfigurationSource(conf);
            this.resourceFinder.addHadoopConfigurationSource(conf);
            log.debug("Non-empty Hadoop Configuration arrived");
        } else {
            log.error("Empty Hadoop Configuration arrived");
        }
    }

    @Override
    public Configuration getConf() {
        return this.hadoopConfiguration;
    }

    protected MapredContext getMapReduceContext() {
        return this.mapReduceContext;
    }

    protected MultisourcePropertyReader getPropertyReader() {
        return propertyReader;
    }

    public ResourceFinder getResourceFinder() {
        return resourceFinder;
    }

    protected transient String udfFunctionName;

    public BasicUDF(String udfFunctionName) {
        this.udfFunctionName = udfFunctionName;

        // init property reader
        this.propertyReader = new MultisourcePropertyReader();
        if (this.propertyReader.addClasspathPropertyFileSource(DEFAULT_CLASSPATH_PROPERTIES_FILE)) {
            log.info("Found default configuration in classpath, file " + DEFAULT_CLASSPATH_PROPERTIES_FILE);
        } else {
            log.info("No default configuration, " + DEFAULT_CLASSPATH_PROPERTIES_FILE + " not found in classpath");
        }

        // init resource finder
        this.resourceFinder = new ResourceFinder();

        String resourceAggressiveMode = this.propertyReader.findProperty(PROPERTY_AGGRESSIVE_SEARCH_MODE);
        if (resourceAggressiveMode != null) {
            log.debug("Found aggressive resource search mode property, value is "+resourceAggressiveMode);
            resourceFinder.setAggressiveSearchMode(Boolean.parseBoolean(resourceAggressiveMode));
        }
    }

    @Override
    public String getDisplayString(String[] strings) {
        StringBuilder sb = new StringBuilder();
        sb.append(udfFunctionName);
        sb.append("(");
        if (strings.length > 0) {
            sb.append(strings[0]);

            for (int i = 1; i < strings.length; ++i) {
                sb.append(",");
                sb.append(strings[i]);
            }
        }

        sb.append(")");
        return sb.toString();
    }

    @Override
    public void copyToNewInstance(Object newInstance) throws UDFArgumentException {
        super.copyToNewInstance(newInstance);
        BasicUDF other = (BasicUDF) newInstance;
        other.resourceFinder.setAggressiveSearchMode(this.resourceFinder.isAggressiveSearchMode());
    }


}
