package encryptix.hds.hive.udf.encryption.hybrid.fast;

import encryptix.hds.eah.EAHDecryptionCore;
import encryptix.hds.eah.v1.EAHDecryptionCoreV1;
import encryptix.hds.eah.v1.FormatHelper;
import encryptix.hds.exception.CryptoCoreFailed;
import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.exception.InvalidInputFormat;
import encryptix.hds.hive.exception.InternalException;
import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.exception.WrongDataFormatException;
import encryptix.hds.hive.udf.BasicUDF;
import encryptix.hds.hive.udf.utils.UDFArgumentUtils;
import encryptix.hds.keymanagement.loader.PrivateKeyLoader;
import encryptix.hds.resourcemanagement.loader.StringLoader;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hive.ql.exec.Description;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.exec.UDFArgumentLengthException;
import org.apache.hadoop.hive.ql.exec.UDFArgumentTypeException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.UDFType;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDFUtils;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.PrimitiveObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorConverter;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.io.Reader;
import java.security.*;

/**
 * This is UDF for encryption by hybrid schema with ECIES and AES,
 * <p/>
 * NOT threadsafe implementation, 'cause Hive uses every instance in a single thread
 * <p/>
 * Target JVM is 7 with Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction installed, see
 * http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
 *
 * @see EAHEncryptUDF
 */
@UDFType(deterministic = false)
@Description(
        name = "eah_decrypt",
        value = "_FUNC_(x) - returns decrypted with the system's private key value",
        extended = "Example:\n  > SELECT _FUNC_('eah:1:BASgeNs+HDU....') FROM src LIMIT 1;\n  decrypted_value_string"
)
public class EAHDecryptUDF extends BasicUDF {

    private static final Log log = LogFactory.getLog(EAHDecryptUDF.class);

    public static final String PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED = "eah.decrypt.onwrongkey.fallback";

    public static final String PROPERTY_PRIVATE_KEY_SOURCE = "eah.decrypt.key.private.source";

    public static final String PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE = "eah.decrypt.key.private.password.source";

    /*
      Our UDF can be initialized few times on different stages (query compile, MR init), on later stages SessionState
      may be unavailable. Also UDF can be serialized/de-serialized and cloned. So we need to take care about proper
      initialization and save state.
     */
    // Do we need initial configuration
    protected boolean configurationLookupRequired = true;

    // Key resource configured to survive multiple inits, serialization and clone
    protected String configurationPrivateKeySource = null;

    // Key passwordresource configured to survive multiple inits, serialization and clone
    protected String configurationPrivateKeyPasswordSource = null;

    // Fallback mode,  configured to survive multiple inits, serialization and clone
    private String configurationFallbackToInputOnWrongKey = null;

    // Fallback mode, return input if key is wrong
    private boolean fallbackToInputOnWrongKey = false;

//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR", justification = "Initialized in UDF initialize()")
    private transient EAHDecryptionCore decryptionCore;
    private transient PrimitiveObjectInspectorConverter.StringConverter stringConverter;
    private transient GenericUDFUtils.StringHelper stringHelper;

    public EAHDecryptUDF() {
        super("eah_decrypt");
    }

    @SuppressWarnings("CPD-START")
    // Will be refactored later to support other types, this is the reason why it's not BasicTextUDF
    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        // check arguments count
        if (arguments.length != 1) {
            throw new UDFArgumentLengthException("Function requires one argument");
        }

        // check argument category and type
        if (!UDFArgumentUtils.isPrimitiveCategory(arguments[0], PrimitiveObjectInspector.PrimitiveCategory.STRING)) {
            throw new UDFArgumentTypeException(0, "Function takes only string as value for decryption for now");
        }

        // Load properties in a way compatible with serialization and multiple initializations while working on a cluster
        readConfiguration();

        // still here?! Well, let's init cryptographic core
        try {
            initCryptographicCore();
        } catch (InternalInitException e) {
            throw new UDFArgumentException(e);
        }

        // init helpers
        this.stringConverter = new PrimitiveObjectInspectorConverter.StringConverter((PrimitiveObjectInspector) arguments[0]);
        this.stringHelper = new GenericUDFUtils.StringHelper(PrimitiveObjectInspector.PrimitiveCategory.STRING);

        // send return type
        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    private void readConfiguration() {

        log.debug("Started reading configuration, initial state is " +
                "key: " + this.configurationPrivateKeySource +
                ", password: " + this.configurationPrivateKeyPasswordSource +
                ", fallback: " + this.configurationFallbackToInputOnWrongKey
        );

        // if configuration already initialized - return
        if (!this.configurationLookupRequired) {
            log.debug("Configuration is already read, skipping");
            return;
        }

        // read private key
        if (this.configurationPrivateKeySource == null) {
            this.configurationPrivateKeySource = getPropertyReader().findProperty(PROPERTY_PRIVATE_KEY_SOURCE);
        }

        // read key password source
        if (this.configurationPrivateKeyPasswordSource == null) {
            this.configurationPrivateKeyPasswordSource = getPropertyReader().findProperty(PROPERTY_PRIVATE_KEY_PASSWORD_SOURCE);
        }

        // read fallback
        if (this.configurationFallbackToInputOnWrongKey == null) {
            this.configurationFallbackToInputOnWrongKey = getPropertyReader().findProperty(PROPERTY_ON_WRONG_KEY_FALLBACK_ENABLED, "false");
            this.fallbackToInputOnWrongKey = Boolean.parseBoolean(this.configurationFallbackToInputOnWrongKey);
        }

        log.debug("Finished reading configuration, state is " +
                "key: " + this.configurationPrivateKeySource +
                ", password: " + this.configurationPrivateKeyPasswordSource +
                ", fallback: " + this.configurationFallbackToInputOnWrongKey
        );

        // private key is the only mandatory field, if it was read - we don't need to update configuration anymore
        if (this.configurationPrivateKeySource != null) {
            log.debug("Switching configurationLookupRequired off");
            this.configurationLookupRequired = false;
        }
    }

    protected void initCryptographicCore() throws InternalInitException {
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());

        // Get key resource
        Reader privateKeyResourceReader = getResourceFinder().getResource(this.configurationPrivateKeySource);
        if (privateKeyResourceReader == null) {
            throw new InternalInitException("Failed to find and open private key while initialization from " + this.configurationPrivateKeySource + ". Check configuration.");
        }

        // Get password resource
        Reader keyPasswordResource = getResourceFinder().getResource(this.configurationPrivateKeyPasswordSource);
        // Read password
        String keyPassword = null;
        if (keyPasswordResource != null) {
            try {
                keyPassword = StringLoader.readString(keyPasswordResource);
            } catch (IOException e) {
                throw new InternalInitException("Failed to read private key password while initialization from the source configured " + this.configurationPrivateKeyPasswordSource + ". Check configuration", e);
            }
        }

        // Read Private Key
        PrivateKey privateKey;
        try {
            privateKey = PrivateKeyLoader.readPrivateKey(privateKeyResourceReader, keyPassword);
        } catch (Exception e) {
            throw new InternalInitException("Failed to read private key while initialization. Check configuration.", e);
        }

        // Init encryption core
        try {
            this.decryptionCore = new EAHDecryptionCoreV1(privateKey);
        } catch (CryptoInitializationFailed e) {
            throw new InternalInitException("Crypto core initialization failed", e);
        }
    }

    @SuppressWarnings("CPD-END")
    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException {

        // null in - null out
        if (arguments[0] == null || arguments[0].get() == null) {
            return null;
        }

        String value = (String) this.stringConverter.convert(arguments[0].get());

        // I'm pretty sure that direct string compare will be faster than parse version, decode and run switch for few versions
        if (value.startsWith(FormatHelper.FORMAT_SIGNATURE)) {
            try {
                return this.stringHelper.setReturnValue(this.decryptionCore.decrypt(value));
            } catch (CryptoInitializationFailed cryptoInitializationFailed) {
                throw new InternalInitException("Crypto core failed on internal re-initialization", cryptoInitializationFailed);
            } catch (CryptoCoreFailed cryptoCoreFailed) {
                // if fallback enabled and wrong padding - fallback
                if (fallbackToInputOnWrongKey && cryptoCoreFailed.getCause() instanceof BadPaddingException) {
                    return this.stringHelper.setReturnValue(value);
                } else throw new InternalException("Crypto core failed on decryption", cryptoCoreFailed);
            } catch (InvalidInputFormat invalidInputFormat) {
                // TODO: Same situation when EC block damaged, need to separate
                throw new WrongDataFormatException("Format is not parsed properly for value " + value);
            }
        } else
            throw new WrongDataFormatException("Format signature is not recognized or version is not supported for value " + value);
    }

    @Override
    public void copyToNewInstance(Object newInstance) throws UDFArgumentException {
        super.copyToNewInstance(newInstance);
        EAHDecryptUDF other = (EAHDecryptUDF) newInstance;
        other.configurationLookupRequired = this.configurationLookupRequired;
        other.configurationPrivateKeySource = this.configurationPrivateKeySource;
        other.configurationPrivateKeyPasswordSource = this.configurationPrivateKeyPasswordSource;
        other.configurationFallbackToInputOnWrongKey = this.configurationFallbackToInputOnWrongKey;
        other.fallbackToInputOnWrongKey = this.fallbackToInputOnWrongKey;
    }

}
