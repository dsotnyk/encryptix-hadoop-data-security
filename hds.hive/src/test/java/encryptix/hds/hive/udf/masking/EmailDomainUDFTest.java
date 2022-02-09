package encryptix.hds.hive.udf.masking;

import encryptix.hds.hive.udf.BasicTextUDFTest;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.junit.Assert;
import org.junit.Test;

public class EmailDomainUDFTest extends BasicTextUDFTest {

    String[][] mailsToTest = {
            {"name@domain", "domain"},
            {"name@domain.com.com", "domain.com.com"},
            {"name@name2@domain.com.com", "domain.com.com"},
            {"@name@name2@domain.com", "domain.com"},
            {"@name@name2@domain.com@", ""},
            {"@", ""},
            {"name@", ""},
            {"@name@", ""},
            {"@domain.com", "domain.com"},
            {"@domain.com@", ""},
            {"", ""},
            {"@@@", ""}
    };

    public EmailDomainUDFTest() throws UDFArgumentException {
        super(new EmailDomainUDF());
    }

    @Test
    public void testCutEmailDomain() throws HiveException {
        for (String[] mailToTest : mailsToTest) {
            Assert.assertEquals(mailToTest[1], udfEvaluate(mailToTest[0]));
        }
    }

}
