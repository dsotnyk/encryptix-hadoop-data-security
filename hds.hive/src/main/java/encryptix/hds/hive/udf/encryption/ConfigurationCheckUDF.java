package encryptix.hds.hive.udf.encryption;


import encryptix.hds.eah.v1.EAHDecryptionCoreV1;
import encryptix.hds.eah.v1.EAHEncryptionCoreV1;
import encryptix.hds.encryption.Version;
import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.hive.property.MultisourcePropertyReader;
import encryptix.hds.hive.udf.BasicUDF;
import encryptix.hds.hive.udf.encryption.hybrid.fast.EAHDecryptUDF;
import encryptix.hds.hive.udf.encryption.hybrid.fast.EAHEncryptUDF;
import encryptix.hds.hive.udf.utils.TextReport;
import encryptix.hds.keymanagement.loader.PrivateKeyLoader;
import encryptix.hds.keymanagement.loader.PublicKeyLoader;
import encryptix.hds.resourcemanagement.loader.StringLoader;
import org.apache.hadoop.hive.ql.exec.Description;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDFUtils;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.PrimitiveObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.Reader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

/**
 * This UDF checks crypto configuration and returns report
 */
@Description(
        name = "eah_ccheck",
        value = "_FUNC_(x) - prints configuration values and makes basic checks",
        extended = "Example:\n  > SELECT _FUNC_() FROM src LIMIT 1;\n  property values and emulation results"
)
public class ConfigurationCheckUDF extends BasicUDF {

    private transient GenericUDFUtils.StringHelper stringHelper;

    private transient TextReport textReport;

    public ConfigurationCheckUDF() {
        super("eah_ccheck");
    }

    @Override
    public ObjectInspector initialize(ObjectInspector[] objectInspectors) throws UDFArgumentException {
        this.stringHelper = new GenericUDFUtils.StringHelper(PrimitiveObjectInspector.PrimitiveCategory.STRING);
        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] deferredObjects) throws HiveException {

        // init report
        textReport = new TextReport();

        textReport.addHeader("Application integrity");
        textReport.addListHeader("Artifacts");
        textReport.addListItem("Encryption core: {0}", Version.getPackageIdentifier());
        textReport.addListItem("Hive wrapper: {0}", encryptix.hds.hive.Version.getPackageIdentifier());
        if (Version.getVERSION().equals(encryptix.hds.hive.Version.getVERSION())) {
            textReport.addInfo("Version match");
        } else {
            textReport.addFatalError("Version mismatch");
        }

        textReport.addHeader("Properties required");
        examineProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE);
        examineProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE);

        textReport.addHeader("Properties optional");
        examineProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE);
        examineProperty(EAHDecryptUDF.PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED);
        examineProperty(BasicUDF.PROPERTY_AGGRESSIVE_SEARCH_MODE);

        textReport.addHeader("Emulate initialization");
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());
        emulatePublicKeyReadAndInit();
        emulatePrivateKeyReadAndInit();

        return stringHelper.setReturnValue(textReport.getReportText());
    }

    /**
     * Reads Public Key and emulates CryptoCore initialization
     */
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "Exception detail hide")
    private void emulatePublicKeyReadAndInit() {

        textReport.addSubHeader("Reading PUBLIC KEY, Run emulation");
        textReport.addInfo("Initialization sequence: [FIND RESOURCE] [OPEN RESOURCE] [READ RESOURCE] [INIT CRYPTOCORE]");

        /*
        Read properties
         */
        String publicKeySourcePropertyValue = getPropertyReader().findProperty(EAHEncryptUDF.PROPERTY_PUBLIC_KEY_SOURCE);

        if (publicKeySourcePropertyValue == null) {
            textReport.addFatalError("Can't find where to get Public Key, no property value");
            return;
        } else {
            textReport.addSuccess("Public Key source property found, value " + publicKeySourcePropertyValue);
        }

        /*
        Read resources
         */
        Reader publicKeyResourceReader = getResourceFinder().getResource(publicKeySourcePropertyValue);

        if (publicKeyResourceReader == null) {
            textReport.addFatalError("Failed to open Public Key resource. See logs or enable debug to get more information");
            return;
        } else {
            textReport.addSuccess("Opened Public Key resource");
        }

        PublicKey publicKey;

        try {
            publicKey = PublicKeyLoader.readPublicKey(publicKeyResourceReader);
            textReport.addSuccess("Public Key was read and decoded successfully");
            if (publicKey == null) {
                textReport.addFatalError("Public Key is empty, internal error");
                return;
            }
        } catch (Exception exception) {
            textReport.addFatalError("Exception while reading Public Key");
            textReport.dumpStackTrace(exception);
            return;
        }

        /*
        Initialize core
         */
        try {
            new EAHEncryptionCoreV1(publicKey);
            textReport.addSuccess("EAHEncryptionCoreV1 initialized properly with this Public Key");
        } catch (CryptoInitializationFailed exception) {
            textReport.addFatalError("EAHEncryptionCoreV1 initialization failed with this Public Key");
            textReport.dumpStackTrace(exception);
        }
    }

    /**
     * Reads Private Key and emulates CryptoCore initialization
     */
    private void emulatePrivateKeyReadAndInit() {

        textReport.addSubHeader("Reading PRIVATE KEY, Run emulation");
        textReport.addInfo("Initialization sequence: [FIND RESOURCE] [OPEN RESOURCE] [READ RESOURCE] [INIT CRYPTOCORE]");

        /*
        Read properties
         */
        String privateKeySourcePropertyValue = getPropertyReader().findProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_SOURCE);

        if (privateKeySourcePropertyValue == null) {
            textReport.addFatalError("Can't find where to get Private Key, no property value");
            return;
        } else {
            textReport.addSuccess("Private Key source property found, value " + privateKeySourcePropertyValue);
        }

        String privateKeyPasswordSourcePropertyValue = getPropertyReader().findProperty(EAHDecryptUDF.PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE);

        if (privateKeyPasswordSourcePropertyValue == null) {
            textReport.addInfo("Can't find where to get Private Key password, no property value. Continue without password");
        } else {
            textReport.addSuccess("Private Key password source property found, value " + privateKeyPasswordSourcePropertyValue);
        }

        /*
        Read resources
         */
        // Get key resource
        Reader privateKeyResourceReader = getResourceFinder().getResource(privateKeySourcePropertyValue);

        if (privateKeyResourceReader == null) {
            textReport.addFatalError("Failed to open Private Key resource. See logs or enable debug to get more information");
            return;
        } else {
            textReport.addSuccess("Opened Private Key resource");
        }

        // Get password resource
        Reader keyPasswordResource = getResourceFinder().getResource(privateKeyPasswordSourcePropertyValue);

        if (keyPasswordResource == null) {
            textReport.addInfo("Private Key Password resource not found");
        } else {
            textReport.addSuccess("Opened Private Key Password resource");
        }

        // Read password
        String keyPassword = null;
        if (keyPasswordResource != null) {
            try {
                keyPassword = StringLoader.readString(keyPasswordResource);
                textReport.addSuccess("Private Key Password was read successfully");
            } catch (IOException exception) {
                textReport.addFatalError("Failed to read Private Key Password");
                textReport.dumpStackTrace(exception);
                return;
            }
        }

        // Read Private Key
        PrivateKey privateKey;
        try {
            privateKey = PrivateKeyLoader.readPrivateKey(privateKeyResourceReader, keyPassword);
            textReport.addSuccess("Private Key was read and decoded successfully");
        } catch (Exception exception) {
            textReport.addFatalError("Failed to read and decode Private Key");
            textReport.dumpStackTrace(exception);
            return;
        }

        /*
        Initialize core
         */

        // Init decryption core
        try {
            new EAHDecryptionCoreV1(privateKey);
            textReport.addSuccess("EAHDecryptionCoreV1 initialized properly with this Private Key");
        } catch (CryptoInitializationFailed cryptoInitializationFailed) {
            textReport.addFatalError("EAHDecryptionCoreV1 initialization failed with this Private Key");
            textReport.dumpStackTrace(cryptoInitializationFailed);
        }
    }

    /**
     * Dump property values available
     *
     * @param propertyName Property value to examine
     */
    private void examineProperty(String propertyName) {
        textReport.addListHeader("Property values for {0}", propertyName);
        textReport.addListItem("ACTIVE value by default order is {0}", getPropertyReader().findProperty(propertyName));
        textReport.addListItem("OS Environment value is {0}", MultisourcePropertyReader.readEnvironmentProperty(propertyName));
        textReport.addListItem("Java system value is {0}", MultisourcePropertyReader.readSystemProperty(propertyName));
        textReport.addListItem("Hive session value is {0}", MultisourcePropertyReader.readHiveSessionProperty(propertyName));
        textReport.addListItem("Hive configuration value is {0}", getPropertyReader().readHiveConfigurationProperty(propertyName));
        textReport.addListItem("Property File in Classpath {0} configuration value is {1}", BasicUDF.DEFAULT_CLASSPATH_PROPERTIES_FILE, getPropertyReader().readClassPathPropertyFile(propertyName));
        textReport.addLine();
    }
}
