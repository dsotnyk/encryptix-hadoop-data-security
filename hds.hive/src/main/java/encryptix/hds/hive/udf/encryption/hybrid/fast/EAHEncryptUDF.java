package encryptix.hds.hive.udf.encryption.hybrid.fast;

import encryptix.hds.eah.EAHEncryptionCore;
import encryptix.hds.eah.v1.EAHEncryptionCoreV1;
import encryptix.hds.hive.exception.InternalException;
import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicUDF;
import encryptix.hds.hive.udf.utils.UDFArgumentUtils;
import encryptix.hds.keymanagement.loader.PublicKeyLoader;
import encryptix.hds.exception.CryptoCoreFailed;
import encryptix.hds.exception.CryptoInitializationFailed;
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

import java.io.Reader;
import java.security.*;

@UDFType(deterministic = false)
@Description(
        name = "eah_encrypt",
        value = "_FUNC_(x) - returns encrypted with the system's public key value",
        extended = "Example:\n  > SELECT _FUNC_('name@domain.com') FROM src LIMIT 1;\n  eah:1:BASgeNs+HDUtyKUuzX6xCZK4NPsJtw2t+Kn5PE9vMJqFAystmDrMJJBnUnIrP+kx0VQuLhSF432v63oGWBsQXEUeDuU7LHIliQE5bNoIjIf/LdRcj/TpEmvHAnQnalrwdKP8zcB/TKjJ+Dy8C5+hlkgelMF6snCe2lMcgQR6GT2XwVXee3lxeMahfuiHr9FRe93KL//howuBQE/kA8fuaMrFyYV2DKAHGWxf8vJkeE0Xg7YB16i7Dwn+WqSV8v33FZKwJXo=:+zLlQ9ANfyItRK2klkXfeg==:DPMPbfnSzrti56bG5573j0/wdm73rpXb2qw+OrIycrNqnR6pEYxEAuAkpHkMJYo4ItSD8h/kSWMdmS/wNLTAG1yquZcZwmj7rqAHg9tzLdA=\n"
)
public class EAHEncryptUDF extends BasicUDF {

    private static final Log log = LogFactory.getLog(EAHEncryptUDF.class);

    public static final String PROPERTY_PUBLIC_KEY_SOURCE = "eah.encrypt.key.public.source";

    /*
      Our UDF can be initialized few times on different stages (query compile, MR init), on later stages SessionState
      may be unavailable. Also UDF can be serialized/de-serialized and cloned. So we need to take care about proper
      initialization and save state.
     */
    // Do we need initial configuration
    protected boolean configurationLookupRequired = true;

    // Key resource configured to survive multiple inits, serialization and clone
    protected String configurationPublicKeySource = null;

//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR", justification = "Initialized in UDF initialize()")
    private transient EAHEncryptionCore encryptionCore;
    private transient PrimitiveObjectInspectorConverter.StringConverter stringConverter;
    private transient GenericUDFUtils.StringHelper stringHelper;

    public EAHEncryptUDF() {
        super("eah_encrypt");
    }

    // TODO: Support not only strings
    @SuppressWarnings("CPD-START")
    // Will be refactored later to support other types, this is the reason why it's not BasicTextUDF
    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        // check arguments count
        if (arguments.length != 1) {
            throw new UDFArgumentLengthException("Function requires one arguments, data to encrypt");
        }

        // check argument category and type
        if (!UDFArgumentUtils.isPrimitiveCategory(arguments[0], PrimitiveObjectInspector.PrimitiveCategory.STRING)) {
            throw new UDFArgumentTypeException(0, "Function takes only string as value for encryption for now");
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

        log.debug("Started reading configuration, initial state is key: " + this.configurationPublicKeySource);

        // if configuration already initialized - return
        if (!this.configurationLookupRequired) {
            log.debug("Configuration is already read, skipping");
            return;
        }

        // Read public key source
        if (this.configurationPublicKeySource == null) {
            this.configurationPublicKeySource = getPropertyReader().findProperty(PROPERTY_PUBLIC_KEY_SOURCE);
        }

        log.debug("Finished reading configuration, state is key: " + this.configurationPublicKeySource);

        // public key is the only mandatory field, if it was read - we don't need to update configuration anymore
        if (this.configurationPublicKeySource != null) {
            log.debug("Switching configurationLookupRequired off");
            this.configurationLookupRequired = false;
        }
    }

    /**
     * Init cryptographic core
     *
     * @throws InternalInitException If initialization failed
     */
    // On this step we can use any conversions etc., cause this is one-time init.
    protected void initCryptographicCore() throws InternalInitException {
        // Load EC library
        Security.addProvider(new BouncyCastleProvider());

        // Get public key resource
        Reader publicKeyResourceReader = getResourceFinder().getResource(this.configurationPublicKeySource);
        if (publicKeyResourceReader == null) {
            throw new InternalInitException("Failed to find and open public key while initialization from " + this.configurationPublicKeySource + ". Check configuration.");
        }

        // Read Public Key
        PublicKey publicKey;
        try {
            publicKey = PublicKeyLoader.readPublicKey(publicKeyResourceReader);
        } catch (Exception e) {
            throw new InternalInitException("Failed to read public key while initialization. Check configuration.", e);
        }

        // Init encryption core
        try {
            this.encryptionCore = new EAHEncryptionCoreV1(publicKey);
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

        try {
            return this.stringHelper.setReturnValue(this.encryptionCore.encrypt(value));
        } catch (CryptoInitializationFailed cryptoInitializationFailed) {
            throw new InternalInitException("Crypto core failed on internal re-initialization", cryptoInitializationFailed);
        } catch (CryptoCoreFailed cryptoCoreFailed) {
            throw new InternalException("Crypto core failed on encryption", cryptoCoreFailed);
        }
    }

    @Override
    public void copyToNewInstance(Object newInstance) throws UDFArgumentException {
        super.copyToNewInstance(newInstance);
        EAHEncryptUDF other = (EAHEncryptUDF) newInstance;
        other.configurationLookupRequired = this.configurationLookupRequired;
        other.configurationPublicKeySource = this.configurationPublicKeySource;
    }

}
