package encryptix.hds.exception;

public class ResourceNotFound extends Exception {
    public ResourceNotFound(String message) {
        super(message);
    }

    public ResourceNotFound(Throwable cause) {
        super(cause);
    }

    public ResourceNotFound(String message, Throwable cause) {
        super(message, cause);
    }

}
