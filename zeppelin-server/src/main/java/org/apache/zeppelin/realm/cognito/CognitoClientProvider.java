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
import com.amazonaws.services.cognitoidp.model.*;
import org.mortbay.log.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class CognitoClientProvider {
    private AWSCognitoIdentityProvider cognito;
    private String userPoolClientId;
    private String userPoolId;
    private static final Logger LOG = LoggerFactory.getLogger(CognitoClientProvider.class);

    public CognitoClientProvider(String userPoolClientId, String userPoolId) {
        LOG.info("Setting up CognitoClientProvider");
        this.cognito = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withRegion("eu-central-1")
                .build();
        this.userPoolClientId = userPoolClientId;
        this.userPoolId = userPoolId;
    }

    protected AdminRespondToAuthChallengeResult respondToAuthChallenge(AdminInitiateAuthResult authResponse,
                                                                       Map<String, String> challengeResponses) {
        AdminRespondToAuthChallengeRequest respondToChallengeRequest = new AdminRespondToAuthChallengeRequest();

        respondToChallengeRequest
                .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                .withChallengeResponses(challengeResponses)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withSession(authResponse.getSession());

        // TODO Handle exceptions AWS may return
        return cognito.adminRespondToAuthChallenge(respondToChallengeRequest);
    }

    protected Map<String, String> buildAuthRequest(String username, String password, String hashedValue) {
        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SECRET_HASH", hashedValue);
        return authParams;
    }

    protected AdminInitiateAuthResult initiateAuth(Map<String, String> authParams) {
        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withAuthParameters(authParams);
        return cognito.adminInitiateAuth(authRequest);
    }

    protected ListUsersResult getUserList() {
        ListUsersRequest listUsersRequest = new ListUsersRequest();
        listUsersRequest.setUserPoolId(userPoolId);
        return cognito.listUsers(listUsersRequest);
    }

    protected List<String> getCognitoGroups() {
        ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
        listGroupsRequest.setUserPoolId(userPoolId);
        List<GroupType> listGroupsResult = cognito.listGroups(listGroupsRequest).getGroups();
        List<String> cognitoGroups = new ArrayList<>();
        listGroupsResult.stream().forEach((group) -> cognitoGroups.add(group.getGroupName()));
        return cognitoGroups;
    }

    public AWSCognitoIdentityProvider getCognito() {
        return cognito;
    }
}
