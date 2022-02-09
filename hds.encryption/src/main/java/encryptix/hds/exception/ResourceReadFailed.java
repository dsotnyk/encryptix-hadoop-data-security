package encryptix.hds.exception;

public class ResourceReadFailed extends Exception {
    public ResourceReadFailed(String message) {
        super(message);
    }

    public ResourceReadFailed(Throwable cause) {
        super(cause);
    }

    public ResourceReadFailed(String message, Throwable cause) {
        super(message, cause);
    }

}
