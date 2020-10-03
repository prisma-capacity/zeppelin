/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.zeppelin.realm;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import org.apache.zeppelin.realm.cognito.CognitoJwtVerifier;
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
