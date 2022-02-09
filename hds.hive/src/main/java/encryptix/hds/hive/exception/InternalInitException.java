package encryptix.hds.hive.exception;

import org.apache.hadoop.hive.ql.metadata.HiveException;

public class InternalInitException extends HiveException {
    public InternalInitException(String message) {
        super(message);
    }

    public InternalInitException(Throwable cause) {
        super(cause);
    }

    public InternalInitException(String message, Throwable cause) {
        super(message, cause);
    }
}
