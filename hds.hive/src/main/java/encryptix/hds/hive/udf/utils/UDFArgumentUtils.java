package encryptix.hds.hive.udf.utils;

import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.PrimitiveObjectInspector;


/**
 * Helper class to manage UDF arguments
 */
public class UDFArgumentUtils {

    /**
     * Check that argument type is in listed primitive categories
     *
     * @param argumentDescription Argument to check
     * @param allowedPrimitiveCategories List of primitive categories expected
     * @return argument type is in listed primitive categories
     */
    public static boolean isPrimitiveCategory(ObjectInspector argumentDescription, PrimitiveObjectInspector.PrimitiveCategory... allowedPrimitiveCategories) {

        // is primitive?
        if (!isArgumentPrimitive(argumentDescription)) {
            return false;
        }

        PrimitiveObjectInspector.PrimitiveCategory argumentPrimitiveCategory = ((PrimitiveObjectInspector) argumentDescription).getPrimitiveCategory();

        for (PrimitiveObjectInspector.PrimitiveCategory allowedPrimitiveCategory : allowedPrimitiveCategories) {
            // you know why I'm using ==
            if (argumentPrimitiveCategory == allowedPrimitiveCategory) {
                return true;
            }
        }

        return false;

    }

    /**
     * Checks, is argument primitive (getCategory is PRIMITIVE and instance of PrimitiveObjectInspector)
     *
     * @param argumentDescription argument to check
     * @return is argument not null and primitive (getCategory is PRIMITIVE and instance of PrimitiveObjectInspector)
     */
    public static boolean isArgumentPrimitive(ObjectInspector argumentDescription) {
        return argumentDescription != null && argumentDescription instanceof PrimitiveObjectInspector && argumentDescription.getCategory() == ObjectInspector.Category.PRIMITIVE;
    }

}
