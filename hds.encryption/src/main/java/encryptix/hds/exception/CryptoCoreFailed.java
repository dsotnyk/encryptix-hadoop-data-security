package encryptix.hds.exception;

public class CryptoCoreFailed extends Exception {

    public CryptoCoreFailed() {
        super();
    }

    public CryptoCoreFailed(String message) {
        super(message);
    }

    public CryptoCoreFailed(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoCoreFailed(Throwable cause) {
        super(cause);
    }

}
