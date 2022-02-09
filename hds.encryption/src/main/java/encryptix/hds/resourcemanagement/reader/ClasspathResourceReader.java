package encryptix.hds.resourcemanagement.reader;

import encryptix.hds.exception.InitializationFailed;
import encryptix.hds.exception.ResourceNotFound;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

/**
 * Reads resource from classpath, default charset is "ISO-8859-1"
 */
public class ClasspathResourceReader extends ResourceReader {

    private ClassLoader classLoader;

    /**
     * Init, default classloader will be used
     */
    public ClasspathResourceReader() {
        this.classLoader = Thread.currentThread().getContextClassLoader();
        if(this.classLoader == null) {
            this.classLoader = ClasspathResourceReader.class.getClassLoader();
        }
    }

    /**
     * Init, custom classloader will be used
     *
     * @param classLoader Custom classloader
     */
    public ClasspathResourceReader(ClassLoader classLoader) throws InitializationFailed {
        if (classLoader == null) {
            throw new InitializationFailed("ClassLoader is null, can't init ClasspathResourceReader");
        }

        this.classLoader = classLoader;
    }

    /**
     * Set's custom ClassLoader to read resource from
     *
     * @param classLoader ClassLoader to use
     */
    public void setClassLoader(ClassLoader classLoader) throws InitializationFailed {
        if (classLoader == null) {
            throw new InitializationFailed("ClassLoader is null, can't init ClasspathResourceReader");
        }

        this.classLoader = classLoader;
    }

    /**
     * Reads resource, default charset is "ISO-8859-1"
     *
     * @param resource Resource to read
     * @return Reader
     * @throws ResourceNotFound If resource is not found
     */
    @Override
    public Reader getResource(String resource) throws ResourceNotFound {

        // Get classloader and stream
        InputStream resourceStream = this.classLoader.getResourceAsStream(resource);

        if (resourceStream == null) {
            throw new ResourceNotFound("Resource '" + resource + "' wasn't found in ClassPath");
        }

        return new InputStreamReader(resourceStream, conversionCharset);
    }

}
