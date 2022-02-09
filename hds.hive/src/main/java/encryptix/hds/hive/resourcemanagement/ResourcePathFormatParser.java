package encryptix.hds.hive.resourcemanagement;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parse resource path format: type:resource[, type:resource]
 */
public class ResourcePathFormatParser {

    private static final Log log = LogFactory.getLog(ResourcePathFormatParser.class);


    public static final String sourceDelimiter = ",";
    public static final char sourceTypePrefixDelimiter = ':';

    /**
     * Parses resources path format string. Invalid entries skipped
     *
     * @param sourcesDefinitionString Resources path format string
     * @return Ordered map of resources, type : resource
     */
    public static Map<String, String> parseSources(String sourcesDefinitionString) {

        log.debug("Parsing sources " + sourcesDefinitionString);

        Map<String, String> sources = new LinkedHashMap<>();

        if (StringUtils.isBlank(sourcesDefinitionString)) return sources;

        String[] sourcesDefinition = sourcesDefinitionString.split(sourceDelimiter);

        for (String sourceDefinition : sourcesDefinition) {
            int typeDelimiterIndex = sourceDefinition.indexOf(sourceTypePrefixDelimiter);

            if (typeDelimiterIndex > 0) {
                String type = sourceDefinition.substring(0, typeDelimiterIndex);
                String value = sourceDefinition.substring(typeDelimiterIndex + 1, sourceDefinition.length());

                if (StringUtils.isNotBlank(type) && StringUtils.isNotBlank(value)) {
                    log.debug("Added entry, type is " + type + ", value is " + value);
                    sources.put(type.trim(), value.trim());
                }
            } else {
                log.debug("Entry ignored " + sourceDefinition);
            }
        }

        return sources;
    }

}
