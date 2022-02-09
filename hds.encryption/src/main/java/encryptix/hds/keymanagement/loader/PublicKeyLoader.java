package encryptix.hds.keymanagement.loader;

import encryptix.hds.exception.InvalidResourceFormat;
import encryptix.hds.exception.ResourceNotFound;
import encryptix.hds.exception.ResourceReadFailed;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.Reader;
import java.security.PublicKey;

/**
 * Public key loader from the source
 */
public class PublicKeyLoader {

    /**
     * Reads public key from the source
     *
     * @return Public key
     * @throws ResourceNotFound Null source provided
     * @throws ResourceReadFailed Source can't be read
     * @throws InvalidResourceFormat Source can't be parsed to Public Key
     */
    public static PublicKey readPublicKey(Reader source) throws ResourceNotFound, ResourceReadFailed, InvalidResourceFormat {

        if (source == null) {
            throw new ResourceNotFound("Public key file source is empty");
        }

        // Read content
        Object keyPair;
        try (PEMParser keyReader = new PEMParser(source)) {
            keyPair = keyReader.readObject();
        } catch (IOException e) {
            throw new ResourceReadFailed("Public key source found, but can't be read", e);
        }

        // Parse content
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        try {
            return converter.getPublicKey((SubjectPublicKeyInfo) keyPair);
        } catch (PEMException e) {
            throw new InvalidResourceFormat("Public key source and read, but can't be parsed", e);
        }
    }


}
