package encryptix.hds.exception;

public class InvalidInputFormat extends Exception {
    public InvalidInputFormat(String message) {
        super(message);
    }

    public InvalidInputFormat(Throwable cause) {
        super(cause);
    }

    public InvalidInputFormat(String message, Throwable cause) {
        super(message, cause);
    }

}
