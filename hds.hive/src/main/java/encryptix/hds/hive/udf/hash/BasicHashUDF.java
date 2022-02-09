package encryptix.hds.hive.udf.hash;

import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.hash.DigestAlgorithm;
import encryptix.hds.hash.StreamedDigestGenerator;
import encryptix.hds.hive.exception.InternalInitException;
import encryptix.hds.hive.udf.BasicTextUDF;

// TODO : Javadoc
// TODO : VectorExpression
/* TODO : Add support of VARCHAR and CHAR.
 * See https://cwiki.apache.org/confluence/display/Hive/LanguageManual+Types#LanguageManualTypes-StringTypes
 * See GenericUDFBaseTrim
 */
public abstract class BasicHashUDF extends BasicTextUDF {

    protected transient StreamedDigestGenerator digestGenerator;
    protected transient boolean caseInsensitive = false;

    public BasicHashUDF(String udfFunctionName, DigestAlgorithm digestAlgorithm) throws InternalInitException {
        super(udfFunctionName);
        try {
            this.digestGenerator = new StreamedDigestGenerator(digestAlgorithm);
        } catch (CryptoInitializationFailed e) {
            throw new InternalInitException("Failed to init digest algorith "+digestAlgorithm.getAlgorithmName(), e);
        }
    }

    public BasicHashUDF(String udfFunctionName, DigestAlgorithm digestAlgorithm, boolean caseInsensitive) throws InternalInitException {
        this(udfFunctionName, digestAlgorithm);
        this.caseInsensitive = caseInsensitive;
    }

    @Override
//    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "DM_CONVERT_CASE", justification = "We are using default locale as well as Hive itself in Lower() function, see org.apache.hadoop.hive.ql.udf.generic.GenericUDFLower")
    protected String processValue(String value) {
        // Yes, we are using default locale as well as Hive itself in Lower() function, see org.apache.hadoop.hive.ql.udf.generic.GenericUDFLower
        return digestGenerator.hexDigest(caseInsensitive ? value.toLowerCase(): value);
    }
}
