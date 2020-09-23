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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class CognitoRealmTest {

    ZeppelinConfiguration zeppelinConfiguration;
    CognitoRealm cognito;
    @Before
    public void setup() throws Exception {
        URL resourcePath = this.getClass().getClassLoader().getResource("shiro.ini");
        cognito = new CognitoRealm();
        IniRealm iniRealm = new IniRealm(resourcePath.getPath());
        Ini ini = iniRealm.getIni();
//        cognito.setUserPoolClientId(ini.getSectionProperty("main", "cognitoRealm.userPoolClientId"));
//        cognito.setUserPoolUrl(ini.getSectionProperty("main", "cognitoRealm.userPoolUrl"));
//        cognito.setUserPoolId(ini.getSectionProperty("main", "cognitoRealm.userPoolId"));
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
//        cognito.setUserPoolId("wXe4T5v");
        assertNotNull(cognito.getCognitoIdentityProvider());
    }

    @Test
    public void testInitiateAuthRequest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException{
        Method method = CognitoRealm.class.getDeclaredMethod("initiateAuthRequest", Map.class);
        method.setAccessible(true);
        final Map<String, String> authParams = new HashMap<>();
        String username = "TODO";
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", "TODO");
        authParams.put("SECRET_HASH", SecretHashCalculator.calculate
                ("TODO", "TODO", username));
        System.out.println(method.invoke(cognito, authParams));


    }

    @Test
    public void testRespondToChallengeAuthRequest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException{
        String username = "s.ilievska.10@gmail.com";

        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken();
        usernamePasswordToken.setPassword("TODO - longer or 16 chars".toCharArray());
        usernamePasswordToken.setUsername(username);

        CognitoRealm uut = new CognitoRealm();

        uut.doGetAuthenticationInfo(usernamePasswordToken);
    }
}