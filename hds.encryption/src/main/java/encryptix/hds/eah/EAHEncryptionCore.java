
package encryptix.hds.eah;

import encryptix.hds.exception.CryptoCoreFailed;
import encryptix.hds.exception.CryptoInitializationFailed;

public interface EAHEncryptionCore {

    /**
     * Encrypt string to EAH format with PublicKey
     *
     * @param value Value to encrypt
     * @return EAH format string
     *
     * @throws CryptoInitializationFailed
     * @throws CryptoCoreFailed
     */
    String encrypt(String value) throws CryptoInitializationFailed, CryptoCoreFailed;
}
