package encryptix.hds.hive.exception;

import org.apache.hadoop.hive.ql.metadata.HiveException;

public class WrongDataFormatException extends HiveException {
    public WrongDataFormatException(String message) {
        super(message);
    }

    public WrongDataFormatException(Throwable cause) {
        super(cause);
    }

    public WrongDataFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
