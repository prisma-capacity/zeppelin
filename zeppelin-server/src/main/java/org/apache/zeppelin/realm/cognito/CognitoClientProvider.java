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

import java.util.HashMap;
import java.util.Map;

public class CognitoClientProvider {
    private AWSCognitoIdentityProvider cognito;
    private String userPoolClientId;
    private String userPoolId;

    public CognitoClientProvider(String userPoolClientId, String userPoolId) {
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

    protected AdminInitiateAuthResult initiateAuthRequest(Map<String, String> authParams) {
        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withAuthParameters(authParams);

        // TODO Handle exceptions AWS may return
        return cognito.adminInitiateAuth(authRequest);
    }



    protected ListUsersResult getUserList() {
        ListUsersRequest listUsersRequest = new ListUsersRequest();
        listUsersRequest.setUserPoolId(userPoolId);
        return cognito.listUsers(listUsersRequest);
    }

    public AWSCognitoIdentityProvider getCognito() {
        return cognito;
    }
}
