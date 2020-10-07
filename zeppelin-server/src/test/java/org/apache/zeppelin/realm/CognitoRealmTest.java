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

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.UserNotFoundException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.zeppelin.realm.cognito.CognitoClientProvider;
import org.apache.zeppelin.realm.cognito.CognitoJwtVerifier;
import org.apache.zeppelin.realm.cognito.CognitoRealm;
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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CognitoRealmTest {
    private static final Logger LOG = LoggerFactory.getLogger(CognitoRealmTest.class);

    CognitoRealm uut;
    String username;
    String password;
    AWSCognitoIdentityProvider cognito;

    CognitoJwtVerifier cognitoJwtVerifier;
    CognitoClientProvider cognitoClientProvider;

    @Before
    public void setup() throws IOException {
        Properties props = PropertiesHelper.getProperties(CognitoRealm.class);
        username = props.getProperty("username");
        password = props.getProperty("password");
        String userPoolId = props.getProperty("userPoolId");
        String userPoolClientId = props.getProperty("userPoolClientId");
        String userPoolUrl = props.getProperty("userPoolUrl");
        String userPoolClientSecret = props.getProperty("userPoolClientSecret");
        uut = new CognitoRealm();

        uut.setUserPoolId(userPoolId);
        uut.setUserPoolClientId(userPoolClientId);
        uut.setUserPoolUrl(userPoolUrl);
        uut.setUserPoolClientSecret(userPoolClientSecret);

        cognitoJwtVerifier = mock(CognitoJwtVerifier.class);
        cognitoClientProvider = mock(CognitoClientProvider.class);
        cognito = mock(AWSCognitoIdentityProvider.class);

        when(cognitoClientProvider.getCognito()).thenReturn(cognito);
        uut.onInit();
    }

    @Test
    public void doGetAuthenticationInfo_userIsPresentInCognito() throws MalformedURLException, BadJOSEException, ParseException, JOSEException {

        String validToken = "eyJraWQiOiJDZEY5bVA2NHVRWURJMXVucFJTcldPdDN1MmlyMlNvSysrXC92M0hsaHdnOD0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3OTc2ZTg4OS04NWFlLTRhMjQtOWQ0YS1lODljZmJkNzdmYWUiLCJhdWQiOiIzYTBiZmpxbHRjYTB2N3RrdmRyYzZscTM5IiwiY29nbml0bzpncm91cHMiOlsiRGV2ZWxvcG1lbnQiXSwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV2ZW50X2lkIjoiZWIzNzQ3ZDEtOTNiZC00NDNkLWEyMGItZmY5MTEwNTFkNGNhIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2MDEyOTMxNDQsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbVwvZXUtY2VudHJhbC0xX2NHS055V2ZLOSIsImNvZ25pdG86dXNlcm5hbWUiOiJzaW1vbmEuaWxpZXZza2EiLCJleHAiOjE2MDEzNzk1NDQsImlhdCI6MTYwMTI5MzE0NCwiZW1haWwiOiJzaW1vbmEuaWxpZXZza2FAcHJpc21hLWNhcGFjaXR5LmV1In0.U_Pb8dok7GM846SofG8dzMuQXvO9GSzW366TX48bZhZzlbTXTsQPoLWhe7oTVFbqyDUGwgk0RrlxMQRigV1AYDNlBfztmG4ByKabjkUquum57qVlJqieYWQlePK-waqRCUAjRXHhAfu_SkKfRlrp1Cm2Pp4lEomFb5DQXIH_d-c_Y3AGbFt8wd1mo_Yu4su-4X9nb67K8Ll0Kc84JS73_9wJcmEoS9rw5yKi-GJDUBO7Rk0tiOIdIezLhSp5gBc5Ym8CuTHgtPhrt8wRPwrvf44xNW-2cF_htoyAr-vTb73vIrgh15magGuEKP4QFt93qETP4a0BpXtcgE10m5Tapw";
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken();
        usernamePasswordToken.setPassword(password.toCharArray());
        usernamePasswordToken.setUsername(username);

        AdminInitiateAuthResult adminInitiateAuthResult = mock(AdminInitiateAuthResult.class);

        when(cognito.adminInitiateAuth(any())).thenReturn(adminInitiateAuthResult);
        when(adminInitiateAuthResult.getChallengeName()).thenReturn(null);

        AuthenticationResultType authResult = mock(AuthenticationResultType.class);

        when(adminInitiateAuthResult.getAuthenticationResult()).thenReturn(authResult);
        when(authResult.getIdToken()).thenReturn(validToken);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().claim("cognito:username", username).build();
        when(cognitoJwtVerifier.verifyJwt(any())).thenReturn(jwtClaimsSet);

        AuthenticationInfo authenticationInfo = uut.doGetAuthenticationInfo(usernamePasswordToken);

        PrincipalCollection principals = authenticationInfo.getPrincipals();
        assertEquals(username, principals.toString());
        assertEquals(password, authenticationInfo.getCredentials());
    }

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void doGetAuthenticationInfo_userIsNotPresentInCognito() {
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken();
        usernamePasswordToken.setPassword(password.toCharArray());
        usernamePasswordToken.setUsername(username);

        when(cognito.adminInitiateAuth(any())).thenThrow(new UserNotFoundException("Cognito could not find the user"));

        try {
            uut.doGetAuthenticationInfo(usernamePasswordToken);
            fail();
            LOG.info("Test failed! Was supposed to throw an exception.");
        } catch (Exception e) {
            assertEquals(UserNotFoundException.class, e.getCause().getClass());
        }
    }


}