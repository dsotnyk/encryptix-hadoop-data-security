package encryptix.hds.resourcemanagement.loader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;

/**
 * Loads text from resource
 */
public class StringLoader {

    public static String readString(Reader resource) throws IOException {

        char[] buffer = new char[2048];

        BufferedReader bufferedReader = new BufferedReader(resource);

        StringBuilder builder = new StringBuilder();

        int charactersRead;

        while ((charactersRead = bufferedReader.read(buffer)) > -1) {
            builder.append(buffer, 0, charactersRead);
        }

        return builder.toString();
    }
}
