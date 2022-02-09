package encryptix.hds.exception;

public class InitializationFailed extends Exception {

    public InitializationFailed() {
        super();
    }

    public InitializationFailed(String message) {
        super(message);
    }

    public InitializationFailed(String message, Throwable cause) {
        super(message, cause);
    }

    public InitializationFailed(Throwable cause) {
        super(cause);
    }

}
