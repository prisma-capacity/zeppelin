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
import com.amazonaws.services.cognitoidp.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CognitoClient {
    private final AWSCognitoIdentityProvider cognito;
    private final String userPoolClientId;
    private final String userPoolId;
    private static final Logger LOG = LoggerFactory.getLogger(CognitoClient.class);

    public CognitoClient(String userPoolClientId, String userPoolId, CognitoClientProvider clientProvider) {
        this.cognito = clientProvider.getCognito();
        this.userPoolClientId = userPoolClientId;
        this.userPoolId = userPoolId;
    }

    protected AdminRespondToAuthChallengeResult respondToAuthChallenge(ChallengeNameType challengeNameType, AdminInitiateAuthResult authResponse,
                                                                       Map<String, String> challengeResponses) {
        AdminRespondToAuthChallengeRequest respondToChallengeRequest = new AdminRespondToAuthChallengeRequest();

        respondToChallengeRequest
                .withChallengeName(challengeNameType)
                .withChallengeResponses(challengeResponses)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withSession(authResponse.getSession());

        // TODO Handle exceptions AWS may return
        return cognito.adminRespondToAuthChallenge(respondToChallengeRequest);
//        return cognito.respondToAuthChallenge(respondToChallengeRequest);
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

    protected InitiateAuthResult initiateAuth2(Map<String, String> authParams) {
        final InitiateAuthRequest authRequest = new InitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .withClientId(userPoolClientId)
                .withAuthParameters(authParams);
        return cognito.initiateAuth(authRequest);
    }

    public VerifySoftwareTokenResult verifySoftwareTokenForAppMFA(final String session, final String code) throws Exception {
        LOG.info("In verifySoftwareTokenForAppMFA");
        try {
            LOG.info("Code " + code);
            final VerifySoftwareTokenRequest verifySoftwareTokenRequest = new VerifySoftwareTokenRequest();
//            if (result.getAuthenticationResult() != null) {
////                verifySoftwareTokenRequest.setAccessToken(result.getAuthenticationResult().getAccessToken());
//            }
            if (session != null) {
                LOG.info("setSession");
                verifySoftwareTokenRequest.setSession(session);
            }
            verifySoftwareTokenRequest.setUserCode(code);// 6 digit code from google Auth
            final VerifySoftwareTokenResult verifySoftwareTokenResult = cognito
                    .verifySoftwareToken(verifySoftwareTokenRequest);

            LOG.info("Software token verified");

            LOG.info(verifySoftwareTokenResult.getSession());
            return verifySoftwareTokenResult;

        } catch (final Exception e) {
            LOG.info("Software token NOT verified");
            LOG.error(e.getMessage());
        }
        return null;
    }

    public void registerSoftwareMFAPreferences(final String username, final String userPoolId) {
        LOG.info("registerSoftwareMFAPreferences - start");
        try {
            final SoftwareTokenMfaSettingsType softwareTokenMfaSettings = new SoftwareTokenMfaSettingsType()
                    .withPreferredMfa(true)
                    .withEnabled(true);

            final AdminSetUserMFAPreferenceRequest adminSetUserMFAPreferenceRequest = new AdminSetUserMFAPreferenceRequest()
                    .withSoftwareTokenMfaSettings(softwareTokenMfaSettings)
                    .withUsername(username)
                    .withUserPoolId(userPoolId);

            cognito.adminSetUserMFAPreference(adminSetUserMFAPreferenceRequest);
            LOG.info("SoftwareMFAPreferences set sucessfully");
        }
        catch(Exception ex){
            LOG.info("registerSoftwareMFAPreferences ex: " + ex.getMessage());
        }
        LOG.info("registerSoftwareMFAPreferences - end");
    }

//    protected InitiateAuthResult initiateAuth(Map<String, String> authParams) {
//        final InitiateAuthRequest authRequest = new InitiateAuthRequest();
//        authRequest.withAuthFlow(AuthFlowType.USER_PASSWORD_AUTH)
//                .withClientId(userPoolClientId)
////                .withUserPoolId(userPoolId)
//                .withAuthParameters(authParams);
//        return cognito.initiateAuth(authRequest);
//    }

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
        listGroupsResult.forEach((group) -> cognitoGroups.add(group.getGroupName()));
        return cognitoGroups;
    }

    public AWSCognitoIdentityProvider getCognito() {
        return cognito;
    }
}
