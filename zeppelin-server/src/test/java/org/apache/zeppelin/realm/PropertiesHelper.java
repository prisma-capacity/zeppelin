package org.apache.zeppelin.realm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PropertiesHelper {
    private static final Logger LOG = LoggerFactory.getLogger(PropertiesHelper.class);

    public static <T> Properties getProperties(Class<T> clazz) throws IOException {
        Properties prop = new Properties();
        String propFile = "aws.cognito.properties";
        InputStream inputStream = clazz.getClassLoader().getResourceAsStream(propFile);
        if (inputStream != null) {
            prop.load(inputStream);
        } else {
            LOG.info("AWS Cognito properties '" + propFile + "' are not set or file cannot be found");
            throw new FileNotFoundException("AWS Cognito properties '" + propFile + "' are not set or file cannot be found");
        }
        return prop;
    }
}
