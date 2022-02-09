
package encryptix.hds.eah.v1;

import encryptix.hds.eah.EAHFormatHelper;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/**
 * EAHv1 format helper
 */
public class FormatHelper {
    /**
     * Output format version
     */
    public static final int VERSION = 1;

    /**
     * Output format delimiter
     */
    public static final String SERIALIZED_BLOCK_DELIMITER = ":";

    /**
     * EAHv1 signature for quick check with String.startWith
     */
    public static final String FORMAT_SIGNATURE = EAHFormatHelper.IDENTIFIER_PREFIX + SERIALIZED_BLOCK_DELIMITER + VERSION;

    /**
     * Conversion String<->byte[] charset. UTF-8 will provide smallest output on ASCII which is the most cases
     */
    public static final String CONVERSION_CHARSET_NAME = "UTF-8";

    /**
     * Conversion charset to speedup conversions (avoid lookup on conversion for every string). Plus few nanoseconds
     */
    public static final Charset CONVERSION_CHARSET = Charset.forName(CONVERSION_CHARSET_NAME);


    /**
     * Creates serialized EAH block prefix
     *
     * @param blockECIESPart Block ECIES part
     * @param aesIV Block AES IV for block-wide IV
     * @return Serialized block
     */
    public static String serializeBlockPrefix(byte[] blockECIESPart, byte[] aesIV) {
        return EAHFormatHelper.IDENTIFIER_PREFIX + SERIALIZED_BLOCK_DELIMITER +
                VERSION + SERIALIZED_BLOCK_DELIMITER +
                serialize(blockECIESPart) + SERIALIZED_BLOCK_DELIMITER +
                serialize(aesIV) + SERIALIZED_BLOCK_DELIMITER;
    }

    /**
     * Serializer. Must be fast and produce compact output
     *
     * @param value Value to serialize
     * @return EAH format serialized value
     */
    public static String serialize(byte[] value) {
        return DatatypeConverter.printBase64Binary(value);
    }

    /**
     * Deserializer. Must be fast
     *
     * @param value Value to deserialize
     * @return Deserialized value
     * @throws IllegalArgumentException
     */
    public static byte[] deserialize(String value) throws IllegalArgumentException {
        return DatatypeConverter.parseBase64Binary(value);
    }

    /**
     * Used to convert string to bytes for processing
     *
     * @param value String to convert
     * @return Bytes of representation
     * @throws UnsupportedEncodingException
     */
    public static byte[] stringToBytes(String value) throws UnsupportedEncodingException {
        return value.getBytes(CONVERSION_CHARSET);
    }

}
