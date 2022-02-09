package encryptix.hds.eah;

import encryptix.hds.exception.CryptoCoreFailed;
import encryptix.hds.exception.CryptoInitializationFailed;
import encryptix.hds.exception.InvalidInputFormat;

public interface EAHDecryptionCore {

    /**
     * Decrypt AEH format with Private Key
     *
     * @param value EAH String
     * @return decrypted value
     *
     * @throws CryptoInitializationFailed
     * @throws CryptoCoreFailed
     * @throws InvalidInputFormat
     */
    String decrypt(String value) throws CryptoInitializationFailed, CryptoCoreFailed, InvalidInputFormat;
}
