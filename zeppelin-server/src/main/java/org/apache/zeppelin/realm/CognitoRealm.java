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
package org.apache.zeppelin.realm;


import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.google.common.annotations.VisibleForTesting;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@code Realm} implementation that uses the CognitoRealm to authenticate users.
 */
public class CognitoRealm extends AuthorizingRealm {
    private static final Logger LOG = LoggerFactory.getLogger(CognitoRealm.class);
    private String userPoolId;
    private String userPoolUrl;
    private String userPoolClientId;
    private String userPoolClientSecret;
    private String name;
    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();
    private CognitoJwtVerifier cognitoJwtVerifier;
    private CognitoClientProvider cognitoClientProvider;
    private AWSCognitoIdentityProvider cognito;

    public void setCognitoClientProvider(CognitoClientProvider cognitoClientProvider) {
        this.cognitoClientProvider = cognitoClientProvider;
        if (cognitoClientProvider != null) {
            this.cognito = this.cognitoClientProvider.getCognito();
        }
    }

    public void setCognitoJwtVerifier(CognitoJwtVerifier cognitoJwtVerifier) throws MalformedURLException {
        cognitoJwtVerifier.setCognitoUserPoolUrl(userPoolUrl);
        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
        this.cognitoJwtVerifier = cognitoJwtVerifier;
    }

    public CognitoRealm() throws MalformedURLException {
        super();
        LOG.info("Initializing CognitoRealm");
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    @Override
    public void onInit() {
        super.onInit();
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        LOG.info("doGetAuthorizationInfo: " + principals.toString());
        return new SimpleAuthorizationInfo();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
        String username = userInfo.getUsername();
        String password = String.valueOf(userInfo.getPassword());

        SimpleAuthenticationInfo authenticationInfo = null;
        String hashedValue = null;

        hashedValue = SecretHashCalculator.calculate(userPoolClientId, userPoolClientSecret, username);

        final Map<String, String> authParams = buildAuthRequest(username, password, hashedValue);
        try {
            AdminInitiateAuthResult authResponse = initiateAuth(authParams);

            String challengeName = authResponse.getChallengeName();
            boolean isChallengePresent = StringUtils.isNotBlank(challengeName);

            if (!isChallengePresent) {
                AuthenticationResultType authResult = authResponse.getAuthenticationResult();
                authenticationInfo = buildCognitoAuthenticationInfo(password, authResult.getIdToken());
                return authenticationInfo;
            } else {
                LOG.info("Unexpected Cognito Challenge.");
                return authenticationInfo;
            }
        } catch (Exception e) {
            LOG.info("An exception has occurred.", e);
            throw new RuntimeException("An exception has occurred.", e);
        }
//        else if (ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(challengeName)) {
//            // TODO Remove once done
//            LOG.info("In NEW_PASSWORD_REQUIRED Challenge!");
//
//            final Map<String, String> challengeResponses = buildAuthRequest(username, password, hashedValue);
//            // TODO the new password should come from the client, once user fills out the new password form
//            challengeResponses.put("NEW_PASSWORD", "NewPasswordNewPassword!123#");
//
//            AdminRespondToAuthChallengeResult challengeResponse = respondToAuthChallenge(authResponse, challengeResponses);
//            AuthenticationResultType authResult = challengeResponse.getAuthenticationResult();
//            authenticationInfo = buildCognitoAuthenticationInfo(password, authResult.getIdToken());
//        } else {
//            LOG.info("Cognito Challenge is not the one that is expected.");
//        }
//        return authenticationInfo;
    }

    private SimpleAuthenticationInfo buildCognitoAuthenticationInfo(String password, String idToken) {
        SimpleAuthenticationInfo authenticationInfo = null;
        try {
            JWTClaimsSet idTokenClaims = cognitoJwtVerifier.verifyJwt(idToken);
            authenticationInfo = new SimpleAuthenticationInfo(idTokenClaims.getClaim("cognito:username"), password, this.getName());
        } catch (Exception e) {
            LOG.info("Exception in normal auth: " + e.getMessage());
        }
        return authenticationInfo;
    }

//    private AdminRespondToAuthChallengeResult respondToAuthChallenge(AdminInitiateAuthResult authResponse, Map<String, String> challengeResponses) {
//        AdminRespondToAuthChallengeRequest respondToChallengeRequest = new AdminRespondToAuthChallengeRequest();
//
//        respondToChallengeRequest
//                .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
//                .withChallengeResponses(challengeResponses)
//                .withClientId(userPoolClientId)
//                .withUserPoolId(userPoolId)
//                .withSession(authResponse.getSession());
//
//        // TODO Handle exceptions AWS may return
//        return cognito.adminRespondToAuthChallenge(respondToChallengeRequest);
//    }

    private Map<String, String> buildAuthRequest(String username, String password, String hashedValue) {
        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SECRET_HASH", hashedValue);
        return authParams;
    }

    private AdminInitiateAuthResult initiateAuth(Map<String, String> authParams) {
        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withAuthParameters(authParams);
        return cognito.adminInitiateAuth(authRequest);
    }

    /**
     * Perform a Simple URL check by using {@code URI(url).toURL()}.
     * If the url is not valid, the try-catch condition will catch the exceptions and return false,
     * otherwise true will be returned.
     *
     * @param url
     * @return
     */
    protected boolean isCognitoUrlValid(String url) {
        boolean valid = false;
        try {
            new URI(url).toURL();
            valid = true;
        } catch (URISyntaxException | MalformedURLException e) {
            LOG.error("Cognito url is not valid.", e);
        } finally {
            return valid;
        }
    }

    public void setUserPoolId(String userPoolId) {
        this.userPoolId = userPoolId;
    }


    public void setUserPoolUrl(String userPoolUrl) {
        this.userPoolUrl = userPoolUrl;
    }


    public void setUserPoolClientId(String userPoolClientId) {
        this.userPoolClientId = userPoolClientId;
    }

    public void setUserPoolClientSecret(String userPoolClientSecret) {
        this.userPoolClientSecret = userPoolClientSecret;
    }

}
