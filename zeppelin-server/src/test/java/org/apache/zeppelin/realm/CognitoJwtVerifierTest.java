package org.apache.zeppelin.realm;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Properties;

public class CognitoJwtVerifierTest {
    private static final Logger LOG = LoggerFactory.getLogger(CognitoJwtVerifierTest.class);

    CognitoJwtVerifier uut;
    String cognitoUserPoolUrl;
    String cognitoUserPoolClientId;
    private String cognitoUserPoolId;

    @Before
    public void setup() throws IOException {
        Properties props = PropertiesHelper.getProperties(CognitoJwtVerifier.class);
        cognitoUserPoolUrl = props.getProperty("forJwtVerifierTestPoolUrl");
        cognitoUserPoolClientId = props.getProperty("forJwtVerifierClientId");
        cognitoUserPoolId = props.getProperty("forJwtVerifierPoolId");
        uut = new CognitoJwtVerifier();
        uut.setCognitoUserPoolClientId(cognitoUserPoolClientId);
        uut.setCognitoUserPoolUrl(cognitoUserPoolUrl);
        uut.setCognitoUserPoolId(cognitoUserPoolId);
    }

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void verifyJwt_invalidJwtToken_throwsParseException() throws MalformedURLException, BadJOSEException, ParseException, JOSEException {
        String invalidJwtToken = "eyJrsk21";
        exceptionRule.expect(ParseException.class);
        uut.verifyJwt(invalidJwtToken);
        LOG.info("Test failed! Was supposed to throw an exception.");
    }
}
