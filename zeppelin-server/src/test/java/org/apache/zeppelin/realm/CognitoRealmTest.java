/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.zeppelin.realm;

import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.junit.Before;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.*;

public class CognitoRealmTest {

    CognitoRealm cognito;
    String username;
    String password;

    @Before
    public void setup() throws Exception {
        URL resourcePath = this.getClass().getClassLoader().getResource("shiro.ini");
        cognito = new CognitoRealm();
        Properties props = getProperties();
        username = props.getProperty("username");
        password = props.getProperty("password");
        String userPoolClientId = props.getProperty("userPoolClientId");
        String userPoolClientSecret = props.getProperty("userPoolClientSecret");
        String userPoolId = props.getProperty("userPoolId");
        String userPoolUrl = props.getProperty("userPoolUrl");
        cognito.setUserPoolClientId(userPoolClientId);
        cognito.setUserPoolId(userPoolId);
        cognito.setUserPoolUrl(userPoolUrl);
        cognito.setUserPoolClientSecret(userPoolClientSecret);
    }

    @Test
    public void testGetIniInformation() {
        assertEquals("123456789", cognito.getUserPoolClientId());
        assertEquals("12345678", cognito.getUserPoolId());
        assertEquals("https://test.com", cognito.getUserPoolUrl());
    }

    @Test
    public void testIfCognitoURLIsValid() {
        assertEquals(true, cognito.isCognitoUrlValid("https://test.com"));
    }

    @Test
    public void testIfCognitoURLIsNotValid() {
        assertEquals(false, cognito.isCognitoUrlValid("saddfsdf"));
    }

    @Test
    public void testCognitoConnection() {
        assertNotNull(cognito.getCognito());
    }

    @Test
    public void testInitiateAuthRequest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
        Method method = CognitoRealm.class.getDeclaredMethod("initiateAuthRequest", Map.class);
        method.setAccessible(true);
        final Map<String, String> authParams = new HashMap<>();

        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SECRET_HASH", SecretHashCalculator.calculate
                (cognito.getUserPoolClientId(), cognito.getUserPoolClientSecret(), username));
        AdminInitiateAuthResult authResult = (AdminInitiateAuthResult) method.invoke(cognito, authParams);
        assertNotNull(authResult.getAuthenticationResult().getAccessToken());
    }

    @Test
    public void testRespondToChallengeAuthRequest() {
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken();
        usernamePasswordToken.setPassword(password.toCharArray());
        usernamePasswordToken.setUsername(username);
        cognito.doGetAuthenticationInfo(usernamePasswordToken);
    }

    private Properties getProperties() throws IOException {
        Properties prop = new Properties();
        try {
            String propFile = "aws.cognito.properties";
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream(propFile);
            if (inputStream != null) {
                prop.load(inputStream);
            } else {
                throw new FileNotFoundException("AWS Cognito properties '" + propFile + "' are not set or file cannot be found");
            }
        }catch (Exception e) {
            System.out.println("Exception: " + e);
        } finally {
            return prop;
        }
    }
}