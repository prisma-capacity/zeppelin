/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.realm.cognito;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.GroupType;
import org.apache.zeppelin.realm.PropertiesHelper;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CognitoClientProviderTest {

    CognitoClientProvider cognitoClientProvider;
    AWSCognitoIdentityProvider cognito;
    private static final Logger LOG = LoggerFactory.getLogger(CognitoClientProviderTest.class);

    @Before
    public void setup() throws IOException {
        Properties props = PropertiesHelper.getProperties(CognitoRealm.class);
        String userPoolId = props.getProperty("userPoolId");
        String userPoolClientId = props.getProperty("userPoolClientId");
        cognito = mock(AWSCognitoIdentityProvider.class);

        AWSCognitoIdentityProviderClientBuilder awsIdpClientBuilder = mock(AWSCognitoIdentityProviderClientBuilder.class);
//        PowerMockito.when(AWSCognitoIdentityProviderClientBuilder.standard()).thenReturn(awsIdpClientBuilder);
//        PowerMockito.when(AWSCognitoIdentityProviderClientBuilder.standard().withRegion(anyString())).thenReturn(awsIdpClientBuilder);
//        PowerMockito.when(AWSCognitoIdentityProviderClientBuilder.standard().withRegion(anyString()).build()).thenReturn(cognito);
        when(awsIdpClientBuilder.standard().build()).thenReturn(cognito);
        cognitoClientProvider = new CognitoClientProvider(userPoolClientId, userPoolId);

        List<GroupType> mockedGroups = new ArrayList<>();
        GroupType admin = new GroupType();
        admin.setGroupName("test");
        mockedGroups.add(admin);
        when(cognito.listGroups(any()).getGroups()).thenReturn(mockedGroups);
    }

    @Test
    public void testGetCognitoGroups() {
        List<String> groups = cognitoClientProvider.getCognitoGroups();
        List<String> resultGroups = new ArrayList<>();
        resultGroups.add("test");
        assertEquals(groups, resultGroups);
    }
}