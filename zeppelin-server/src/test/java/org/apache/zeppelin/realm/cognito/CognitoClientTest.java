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
import com.amazonaws.services.cognitoidp.model.GroupType;
import com.amazonaws.services.cognitoidp.model.ListGroupsResult;
import org.apache.zeppelin.realm.PropertiesHelper;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CognitoClientTest {

    private CognitoClient uut;
    private AWSCognitoIdentityProvider cognito;
    private static final Logger LOG = LoggerFactory.getLogger(CognitoClientTest.class);

    @Before
    public void setup() throws IOException {
        Properties props = PropertiesHelper.getProperties(CognitoRealm.class);
        String userPoolId = props.getProperty("userPoolId");
        String userPoolClientId = props.getProperty("userPoolClientId");
        CognitoClientProvider clientProvider = mock(CognitoClientProvider.class);
        cognito = mock(AWSCognitoIdentityProvider.class);
        when(clientProvider.getCognito()).thenReturn(cognito);

        uut = new CognitoClient(userPoolClientId, userPoolId, clientProvider);
    }

    @Test
    public void testGetCognitoGroups() {
        List<GroupType> mockedGroups = new ArrayList<>();
        GroupType admin = new GroupType();
        String expectedGroupName = "test";
        admin.setGroupName(expectedGroupName);
        mockedGroups.add(admin);

        ListGroupsResult listGroupsResult = mock(ListGroupsResult.class);
        when(cognito.listGroups(any())).thenReturn(listGroupsResult);
        when(listGroupsResult.getGroups()).thenReturn(mockedGroups);

        List<String> groups = uut.getCognitoGroups();

        assertTrue(groups.contains(expectedGroupName));
    }
}