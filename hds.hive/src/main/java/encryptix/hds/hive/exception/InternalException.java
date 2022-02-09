package encryptix.hds.hive.exception;

import org.apache.hadoop.hive.ql.metadata.HiveException;

public class InternalException extends HiveException {
    public InternalException(String message) {
        super(message);
    }

    public InternalException(Throwable cause) {
        super(cause);
    }

    public InternalException(String message, Throwable cause) {
        super(message, cause);
    }
}
