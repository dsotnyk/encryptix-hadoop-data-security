package encryptix.hds.exception;

public class CryptoInitializationFailed extends Exception {

    public CryptoInitializationFailed() {
        super();
    }

    public CryptoInitializationFailed(String message) {
        super(message);
    }

    public CryptoInitializationFailed(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoInitializationFailed(Throwable cause) {
        super(cause);
    }

}
