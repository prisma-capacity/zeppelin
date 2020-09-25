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
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.google.gson.Gson;
import com.amazonaws.services.cognitoidp.model.*;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalMap;
import org.apache.zeppelin.common.JsonSerializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

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

    public void setCognitoJwtVerifier(CognitoJwtVerifier cognitoJwtVerifier) throws MalformedURLException {
        LOG.info("setCognitoJwtVerifier: " + cognitoJwtVerifier.toString());
        cognitoJwtVerifier.setCognitoUserPoolUrl(userPoolUrl);
        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
        this.cognitoJwtVerifier = cognitoJwtVerifier;
    }

    private final AWSCognitoIdentityProvider cognito = AWSCognitoIdentityProviderClientBuilder
            .standard()
            .withRegion("eu-central-1")
            .build();

    public CognitoRealm() throws MalformedURLException {
        super();
        LOG.info("Init CognitoRealm");
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    @Override
    public void onInit() {
        super.onInit();
        LOG.info("onInit userPoolUrl: " + userPoolUrl);
        LOG.info("onInit userPoolClientId: " + userPoolClientId);
        LOG.info("onInit userPoolId: " + userPoolId);
        LOG.info("onInit userPoolClientSecret: " + userPoolClientSecret);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        LOG.info("doGetAuthorizationInfo: " + principals.toString());
        return new SimpleAuthorizationInfo();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        LOG.info("doGetAuthenticationInfo: " + token.toString());
        UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
        String username = userInfo.getUsername();
        String password = String.valueOf(userInfo.getPassword());
        // TODO Remove once done - we don't want to log the password ???
        LOG.info("username: " + username);
        LOG.info("password: " + password);

        SimpleAuthenticationInfo authenticationInfo = null;

        String hashedValue = null;

        try {
            hashedValue = SecretHashCalculator.calculate(userPoolClientId, userPoolClientSecret, username);
        } catch (Exception e) {
            LOG.info("Exception in calculating hash: " + e.getMessage());
        }
        // AdminInitiateAuth
        final Map<String, String> authParams = buildAuthRequest(username, password, hashedValue);
        AdminInitiateAuthResult authResponse = initiateAuthRequest(authParams);

        String challengeName = authResponse.getChallengeName();
        boolean isChallengePresent = StringUtils.isNotBlank(challengeName);

        if (!isChallengePresent) {
            // TODO Remove once done
            LOG.info("No challenge to respond to!");

            AuthenticationResultType authResult = authResponse.getAuthenticationResult();

            LOG.info("ACCESS TOKEN is: " + authResult.getAccessToken());

            authenticationInfo = buildCognitoAuthenticationInfo(password, authResult.getIdToken());
        } else if (ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(challengeName)) {
            // TODO Remove once done
            LOG.info("In NEW_PASSWORD_REQUIRED Challenge!");

            final Map<String, String> challengeResponses = buildAuthRequest(username, password, hashedValue);
            // TODO the new password should come from the client, once user fills out the new password form
            challengeResponses.put("NEW_PASSWORD", "NewPasswordNewPassword!123#");

            AdminRespondToAuthChallengeResult challengeResponse = respondToAuthChallenge(authResponse, challengeResponses);
            AuthenticationResultType authResult = challengeResponse.getAuthenticationResult();
            authenticationInfo = buildCognitoAuthenticationInfo(password, authResult.getIdToken());
        } else {
            LOG.info("Cognito Challenge is not the one that is expected.");
        }
        return authenticationInfo;
    }

    private SimpleAuthenticationInfo buildCognitoAuthenticationInfo(String password, String idToken) {
        SimpleAuthenticationInfo authenticationInfo = null;
        try {
            JWTClaimsSet idTokenClaims = cognitoJwtVerifier.verifyJwt(idToken);
            LOG.info("id token claims: " + idTokenClaims.getClaims());
            LOG.info("Getting claim for email: " + idTokenClaims.getClaim("email"));
            authenticationInfo = new SimpleAuthenticationInfo(idTokenClaims.getClaim("email"), password, this.getName());
        } catch (Exception e) {
            LOG.info("Exception in normal auth: " + e.getMessage());
        }
        return authenticationInfo;
    }

    private AdminRespondToAuthChallengeResult respondToAuthChallenge(AdminInitiateAuthResult authResponse, Map<String, String> challengeResponses) {
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

    private Map<String, String> buildAuthRequest(String username, String password, String hashedValue) {
        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SECRET_HASH", hashedValue);
        return authParams;
    }

    private AdminInitiateAuthResult initiateAuthRequest(Map<String, String> authParams) {
        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withAuthParameters(authParams);

        // TODO Handle exceptions AWS may return
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

    public String getUserPoolId() {
        return userPoolId;
    }

    public void setUserPoolId(String userPoolId) {
        this.userPoolId = userPoolId;
    }

    public String getUserPoolUrl() {
        return userPoolUrl;
    }

    public void setUserPoolUrl(String userPoolUrl) {
        this.userPoolUrl = userPoolUrl;
    }

    public String getUserPoolClientId() {
        return userPoolClientId;
    }

    public void setUserPoolClientId(String userPoolClientId) {
        this.userPoolClientId = userPoolClientId;
    }

    public String getUserPoolClientSecret() {
        return userPoolClientSecret;
    }

    public void setUserPoolClientSecret(String userPoolClientSecret) {
        this.userPoolClientSecret = userPoolClientSecret;
    }

    public AWSCognitoIdentityProvider getCognito() {
        return cognito;
    }
}
