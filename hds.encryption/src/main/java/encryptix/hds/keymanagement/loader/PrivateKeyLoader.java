package encryptix.hds.keymanagement.loader;

import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.exception.InvalidResourceFormat;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * Private key loader from a source
 */
public class PrivateKeyLoader {

    /**
     * Reads private key from classpath, see constructor also
     *
     * @return Private key
     * @throws ResourceNotFound No resource in classpath
     * @throws ResourceReadFailed Resource can't be read
     * @throws InvalidResourceFormat Resource can't be parsed to Private Key
     * @throws CryptoInitializationFailed If key is encrypted
     */
    public static PrivateKey readPrivateKey(Reader source) throws ResourceNotFound, ResourceReadFailed, InvalidResourceFormat, CryptoInitializationFailed {
        return readPrivateKey(source, null);
    }

    /**
     * Reads private key from source
     *
     * @param password Password to decrypt private key, if encrypted
     * @return Private key
     * @throws ResourceNotFound Null source provided
     * @throws ResourceReadFailed Source can't be read
     * @throws InvalidResourceFormat Source can't be parsed to Private Key
     * @throws CryptoInitializationFailed If key is encrypted and password wrong
     */
    public static PrivateKey readPrivateKey(Reader source, String password) throws ResourceNotFound, ResourceReadFailed, InvalidResourceFormat, CryptoInitializationFailed {

        if (source == null) {
            throw new ResourceNotFound("Private key file source is empty");
        }

        // Read content
        Object keyObject;
        try (PEMParser pemParser = new PEMParser(source)) {
            keyObject = pemParser.readObject();
        } catch (IOException e) {
            throw new ResourceReadFailed("Private source key found, but can't be read", e);
        }

        // Parse content
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        KeyPair keyPair;
        if (keyObject instanceof PEMEncryptedKeyPair) {
            // Encrypted key - we will use provided password
            if (password == null) {
                throw new CryptoInitializationFailed("Found encrypted private key, but password wasn't provided");
            }

            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            try {
                keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) keyObject).decryptKeyPair(decProv));
            } catch (IOException e) {
                throw new CryptoInitializationFailed("Found encrypted private key, but can't decrypt, is password wrong?", e);
            }
        } else {
            // Unencrypted key - no password needed
            try {
                keyPair = converter.getKeyPair((PEMKeyPair) keyObject);
            } catch (PEMException e) {
                throw new InvalidResourceFormat("Private key found and read, but can't be parsed", e);
            }
        }

        return keyPair.getPrivate();
    }
}
