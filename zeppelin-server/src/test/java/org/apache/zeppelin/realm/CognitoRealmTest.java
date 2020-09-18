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

import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.service.ShiroAuthenticationService;
import org.junit.Before;
import org.junit.Test;

import java.net.URL;

import static org.junit.Assert.*;

public class CognitoRealmTest {
    ZeppelinConfiguration zeppelinConfiguration;

    @Before
    public void clearSystemVariables() {
        System.clearProperty(ZeppelinConfiguration.ConfVars.ZEPPELIN_NOTEBOOK_DIR.getVarName());
    }

    @Before
    public void setup() throws Exception {
        URL shiroPath = this.getClass().getResource("/shiro.ini");
        System.out.println(shiroPath);
        zeppelinConfiguration = new ZeppelinConfiguration(shiroPath);
    }

    @Test
    public void testGetIniInformation(){
        CognitoRealm cognito = new CognitoRealm(zeppelinConfiguration);
        assertEquals("123456789", cognito.getUserPoolClientId());
        assertEquals("12345678", cognito.getUserPoolId());
        assertEquals("https://test.com", cognito.getUserPoolUrl());
    }
}