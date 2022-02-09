package encryptix.hds.hash;


import encryptix.hds.exception.CryptoInitializationFailed;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class StreamedDigestGeneratorTest {

    static StreamedDigestGenerator md2;
    static StreamedDigestGenerator md5;
    static StreamedDigestGenerator sha1;
    static StreamedDigestGenerator sha256;
    static StreamedDigestGenerator sha384;
    static StreamedDigestGenerator sha512;

    @BeforeClass
    public static void initialize() throws CryptoInitializationFailed {
        md2 = new StreamedDigestGenerator(DigestAlgorithm.MD2);
        md5 = new StreamedDigestGenerator(DigestAlgorithm.MD5);
        sha1 = new StreamedDigestGenerator(DigestAlgorithm.SHA1);
        sha256 = new StreamedDigestGenerator(DigestAlgorithm.SHA256);
        sha384 = new StreamedDigestGenerator(DigestAlgorithm.SHA384);
        sha512 = new StreamedDigestGenerator(DigestAlgorithm.SHA512);

    }

    /*
      No need to test other methods except hexDigest, 'cause String hexDigest(String) uses other methods internally
      Expected digests (except MD2) was generated in Linux with a system commands
      echo -n message|md5sum
      echo -n message|sha1sum
      echo -n message|sha256sum
      echo -n message|sha384sum
      echo -n message|sha512sum

      Pay attention, that by default "echo" will add \n to message without -n parameter and this will change digest
     */

    @Test
    public void md2_hexDigestHappyPathTest() {
        Assert.assertEquals("c92c0babdc764d8674bcea14a55d867d", md2.hexDigest("1"));
        Assert.assertEquals("3c8345b995e1b9bf8bfa4ad97596658b", md2.hexDigest("aaabbb"));
        Assert.assertEquals("09b5f457e3b1cf8ca5a321b5df1b003a", md2.hexDigest("99dc60e12d6ea1b454feb55bbe9a64f3"));
    }

    @Test
    public void md5_hexDigestHappyPathTest() {
        Assert.assertEquals("c4ca4238a0b923820dcc509a6f75849b", md5.hexDigest("1"));
        Assert.assertEquals("6547436690a26a399603a7096e876a2d", md5.hexDigest("aaabbb"));
        Assert.assertEquals("ce148c91996f8645bdb4325fb57918f8", md5.hexDigest("99dc60e12d6ea1b454feb55bbe9a64f3"));
    }

    @Test
    public void sha1_hexDigestHappyPathTest() {
        Assert.assertEquals("356a192b7913b04c54574d18c28d46e6395428ab", sha1.hexDigest("1"));
        Assert.assertEquals("68d8572c2662b0f06f723d7d507954fb038b8558", sha1.hexDigest("aaabbb"));
        Assert.assertEquals("604fb2c89721ae0ac015983d9266f3c4459c89db", sha1.hexDigest("99dc60e12d6ea1b454feb55bbe9a64f3"));
    }

    @Test
    public void sha256_hexDigestHappyPathTest() {
        Assert.assertEquals("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", sha256.hexDigest("1"));
        Assert.assertEquals("2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c", sha256.hexDigest("aaabbb"));
        Assert.assertEquals("dbd03fbd0567232497944bfe3b60d6cd07424f24c733561a2ea7357e542673b5", sha256.hexDigest("99dc60e12d6ea1b454feb55bbe9a64f3"));
    }

    @Test
    public void sha384_hexDigestHappyPathTest() {
        Assert.assertEquals("47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776", sha384.hexDigest("1"));
        Assert.assertEquals("93a8ded6ed9ec617e1dbd7b552c0f87b7fee64728297666cc55cc26f08dc2d4d9dbeb22a845abe7101333b5d7f1b57ef", sha384.hexDigest("aaabbb"));
        Assert.assertEquals("0ab23224899cf846c4d2c36433a7b550666ac383b391b99c69af2a7a18979dfdcd73a3160f2121ed91f436dfa788a7c2", sha384.hexDigest("99dc60e12d6ea1b454feb55bbe9a64f3"));
    }

    @Test
    public void sha512_hexDigestHappyPathTest() {
        Assert.assertEquals("4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a", sha512.hexDigest("1"));
        Assert.assertEquals("afdb9638e99117fd7477f3d2d578c6a37a6853945c64e88a81cc8734604cd5afd4fea8c82b1159d943bf1bfc68f6bbcfecd04f61cf5271500f125bd4f756c2ba", sha512.hexDigest("aaabbb"));
        Assert.assertEquals("a60d6fc9e1193d2974c71a762fb4d9cdb84246564b70cfc4467fb638bd6b33d1b57a3591a503e6769bea24138be3c4b06d3cd2775bd680919b72225aaed92438", sha512.hexDigest("99dc60e12d6ea1b454feb55bbe9a64f3"));
    }


    @Test
    public void hexDigestStabilityTest() {

        int count = 1000;

        // Generate test messages
        List<String> testMessages = new ArrayList<>(count);

        for (int i = 0; i < count; i++) {
            testMessages.add(RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500)));
        }

        runHexDigestPerformanceAndStabilityTest(md2, testMessages, null);
        runHexDigestPerformanceAndStabilityTest(md5, testMessages, null);
        runHexDigestPerformanceAndStabilityTest(sha1, testMessages, null);
        runHexDigestPerformanceAndStabilityTest(sha256, testMessages, null);
        runHexDigestPerformanceAndStabilityTest(sha384, testMessages, null);
        runHexDigestPerformanceAndStabilityTest(sha512, testMessages, null);
    }


    @Test
    @Ignore
    public void hexDigestPerformanceAndStabilityTest() {

        int count = 100000;

        // Generate test messages
        List<String> testMessages = new ArrayList<>(count);

        for (int i = 0; i < count; i++) {
            testMessages.add(RandomStringUtils.randomAlphanumeric(RandomUtils.nextInt(30, 500)));
        }

        /**
         * Expected TPS numbers like
         * 29K md2
         * 450K md5
         * 490K sha1
         * 320K sha256
         * 340K sha384
         * 380K sha512
         * We will use 1/3
         */
        runHexDigestPerformanceAndStabilityTest(md2, testMessages, 10);
        runHexDigestPerformanceAndStabilityTest(md5, testMessages, 150);
        runHexDigestPerformanceAndStabilityTest(sha1, testMessages, 170);
        runHexDigestPerformanceAndStabilityTest(sha256, testMessages, 120);
        runHexDigestPerformanceAndStabilityTest(sha384, testMessages, 130);
        runHexDigestPerformanceAndStabilityTest(sha512, testMessages, 120);
    }

    private void runHexDigestPerformanceAndStabilityTest(StreamedDigestGenerator sdg, List<String> messages, Integer expectedKTpS) {

        long start = System.nanoTime();
        for (String message : messages) {
            sdg.hexDigest(message);
        }

        long totalTime = System.nanoTime() - start;
        long tps = TimeUnit.NANOSECONDS.convert(1, TimeUnit.SECONDS) * messages.size() / totalTime;

        if (expectedKTpS != null) {
            Assert.assertTrue(tps > 1000 * expectedKTpS);
        }
    }

}
