package encryptix.hds.exception;

public class InvalidResourceFormat extends Exception {
    public InvalidResourceFormat(String message) {
        super(message);
    }

    public InvalidResourceFormat(Throwable cause) {
        super(cause);
    }

    public InvalidResourceFormat(String message, Throwable cause) {
        super(message, cause);
    }

}
