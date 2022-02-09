package encryptix.hds.hive.udf.masking;

import encryptix.hds.hive.udf.BasicTextUDF;
import org.apache.hadoop.hive.ql.exec.Description;

// TODO : VectorExpression
/* TODO : Add support of VARCHAR and CHAR.
 * See https://cwiki.apache.org/confluence/display/Hive/LanguageManual+Types#LanguageManualTypes-StringTypes
 * See GenericUDFBaseTrim
 */

/**
 * UDF cuts an returns domain name from email
 */
@Description(
        name = "email_domain",
        value = "_FUNC_(x) - returns the domain of the email",
        extended = "Example:\n  > SELECT _FUNC_('name@domain.com') FROM src LIMIT 1;\n  domain.com"
)
public class EmailDomainUDF extends BasicTextUDF {

    public EmailDomainUDF() {
        super("email_domain");
    }

    @SuppressWarnings("PMD.UselessParentheses") // for readability
    @Override
    protected String processValue(String value) {
        int domainStartIndex = value.lastIndexOf('@');
        return (domainStartIndex >= 0) ? value.substring(domainStartIndex + 1, value.length()) : value;
    }
}
