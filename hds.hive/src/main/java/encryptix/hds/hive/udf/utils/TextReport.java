package encryptix.hds.hive.udf.utils;

import org.apache.commons.lang3.StringUtils;

import java.text.MessageFormat;
import java.util.Locale;

/**
 * Class for text reporting from UDF
 */
public class TextReport {

    public static final int DEFAULT_EXCEPTION_DUMP_DEPTH = 10;

    private int exceptionDumpDepth = DEFAULT_EXCEPTION_DUMP_DEPTH;

    private StringBuilder reportContent = new StringBuilder();

    public enum LINE_FORMAT {HEADER, SUBHEADER, PLAIN, LIST_HEADER, LIST_ITEM, SUCCESS, INFO, ERROR, FATAL_ERROR}

    public static final String shortHeaderDelimiter = "==============================================================";

    public static final String shortSubHeaderDelimiter = "--------------------------------------------------------------";

    public static final String whitespace = " ";

    /**
     * Sets exception causes dump depth
     *
     * @param exceptionDumpDepth exception causes dump depth
     */
    public void setExceptionDumpDepth(int exceptionDumpDepth) {
        this.exceptionDumpDepth = exceptionDumpDepth;
    }

    /**
     * Adds empty line to the report
     */
    public void addLine() {
        reportContent.append(System.lineSeparator());
    }

    /**
     * Adds line to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addLine(String message, String... arguments) {
        addLine(LINE_FORMAT.PLAIN, message, arguments);
    }

    /**
     * Adds header to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addHeader(String message, String... arguments) {
        addLine(LINE_FORMAT.HEADER, message, arguments);
    }

    /**
     * Adds sub-header to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addSubHeader(String message, String... arguments) {
        addLine(LINE_FORMAT.SUBHEADER, message, arguments);
    }

    /**
     * Adds list item to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addListItem(String message, String... arguments) {
        addLine(LINE_FORMAT.LIST_ITEM, message, arguments);
    }

    /**
     * Adds list header to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addListHeader(String message, String... arguments) {
        addLine(LINE_FORMAT.LIST_HEADER, message, arguments);
    }

    /**
     * Adds success result record to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addSuccess(String message, String... arguments) {
        addLine(LINE_FORMAT.SUCCESS, message, arguments);
    }

    /**
     * Adds fatal error result record to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addFatalError(String message, String... arguments) {
        addLine(LINE_FORMAT.FATAL_ERROR, message, arguments);
    }

    /**
     * Adds error result record to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addError(String message, String... arguments) {
        addLine(LINE_FORMAT.ERROR, message, arguments);
    }

    /**
     * Adds info record to the report
     *
     * @param message   Message to format, see MessageFormat
     * @param arguments Arguments to add to message
     * @see MessageFormat
     */
    public void addInfo(String message, String... arguments) {
        addLine(LINE_FORMAT.INFO, message, arguments);
    }

    /**
     * Adds line to the report
     *
     * @param lineFormat Line format type
     * @param message    Message to format, see MessageFormat
     * @param arguments  Arguments to add to message
     * @see MessageFormat
     */
    public void addLine(LINE_FORMAT lineFormat, String message, String... arguments) {

        String renderedText = MessageFormat.format(message, arguments);

        switch (lineFormat) {
            case HEADER:
                reportContent
                        .append(shortHeaderDelimiter).append(whitespace)
                        .append(renderedText.toUpperCase(Locale.ENGLISH))
                        .append(whitespace).append(shortHeaderDelimiter)
                        .append(System.lineSeparator());

                break;
            case SUBHEADER:
                reportContent
                        .append(shortSubHeaderDelimiter).append(whitespace)
                        .append(renderedText)
                        .append(shortSubHeaderDelimiter).append(whitespace)
                        .append(System.lineSeparator());

                break;
            case LIST_ITEM:
                reportContent.append(" - ").append(renderedText);
                break;
            case LIST_HEADER:
                reportContent.append(renderedText).append(" :");
                break;
            case SUCCESS:
                reportContent.append("SUCCESS: ").append(renderedText);
                break;
            case ERROR:
                reportContent.append("ERROR: ").append(renderedText);
                break;
            case INFO:
                reportContent.append("INFO: ").append(renderedText);
                break;
            case FATAL_ERROR:
                reportContent.append("!!! FATAL ERROR !!! : ").append(renderedText);
                break;
            default:
                reportContent.append(renderedText);
        }

        reportContent.append(System.lineSeparator());
    }

    /**
     * Dumps exception to the list of causes
     *
     * @param rootException Exception to dump
     */
    public void dumpStackTrace(Exception rootException) {
        addListHeader("EXCEPTION : Exception occurred. Caused by");

        int depth = 0;
        Throwable cause = rootException;
        while (depth++ < exceptionDumpDepth && cause != null) {
            if (StringUtils.isNotEmpty(cause.getMessage())) {
                addListItem(cause.getClass().toString() + " : " + cause.getMessage());
            }
            cause = cause.getCause();
        }
    }

    /**
     * Returns report text
     *
     * @return report text
     */
    public String getReportText() {
        return reportContent.toString();
    }


}
