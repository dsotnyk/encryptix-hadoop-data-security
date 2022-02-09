package encryptix.hds.resourcemanagement.reader;

import encryptix.hds.exception.InitializationFailed;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;

import java.io.Reader;
import java.nio.charset.Charset;

public abstract class ResourceReader {

    /**
     * Default conversion charset
     */
    public Charset conversionCharset = Charset.forName("ISO-8859-1");

    /**
     * Set's custom conversion charset
     *
     * @param conversionCharset Charset to use
     */
    public void setConversionCharset(Charset conversionCharset) throws InitializationFailed {
        if (conversionCharset == null) {
            throw new InitializationFailed("Charset is null, can't init ResourceReader");
        }

        this.conversionCharset = conversionCharset;
    }

    /**
     * Reads resource
     *
     * @param resource Resource to read
     * @return Reader
     * @throws ResourceNotFound If resource is not found
     */
    public abstract Reader getResource(String resource) throws ResourceNotFound, InitializationFailed, ResourceReadFailed;

}
