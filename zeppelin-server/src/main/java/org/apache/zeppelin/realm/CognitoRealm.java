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
import org.apache.zeppelin.common.JsonSerializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
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
    private final HttpClient httpClient;
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
        this.httpClient = new HttpClient();
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
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        LOG.info("doGetAuthenticationInfo: " + token.toString());

        System.out.println("This is in the doGetAuthenticationInfo");
        if(token instanceof UsernamePasswordToken){
            UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
            String username = userInfo.getUsername();

            String password = String.valueOf(userInfo.getPassword());
            String hashedValue = calculateHash(username);

            // AdminInitiateAuth
            final Map<String, String> authParams = buildAuthRequest(username, password, hashedValue);
            AdminInitiateAuthResult authResponse = initiateAuthRequest(authParams);

            // AdminRespondToAuthChallenge
            String challengeName = authResponse.getChallengeName();
            boolean isChallengePresent = StringUtils.isNotBlank(challengeName);

            if (!isChallengePresent) {

                AuthenticationResultType authenticationResult = authResponse.getAuthenticationResult();

                String accessToken = authenticationResult.getAccessToken();

                // parse and verify the jwt token
                try{
                    JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(accessToken);
                }catch(Exception ex){
                    LOG.info("Exception: " + ex.getMessage());
                }
            }
            return new SimpleAuthenticationInfo(username, password, this.getName());
        } else if(token instanceof CognitoToken) {
            CognitoToken cognitoToken = (CognitoToken) token;
            LOG.info("Should have a Cognito Token" + cognitoToken);
            String username = "";
            try{
                cognitoJwtVerifier.setCognitoUserPoolId(userPoolId);
                JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(cognitoToken.id_token);
                username = claims.getStringClaim("cognito:username");
            }catch(Exception ex){
                LOG.info("Exception: " + ex.getMessage());
            }
            return new SimpleAuthenticationInfo(username, cognitoToken.id_token, this.getName());
        }
        return null;
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

    private String calculateHash(String username) {
        return SecretHashCalculator.calculate(userPoolClientId, userPoolClientSecret, username);
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

    protected ListUsersResult getUserList() {
        ListUsersRequest listUsersRequest = new ListUsersRequest();
        listUsersRequest.setUserPoolId(userPoolId);
        return cognito.listUsers(listUsersRequest);
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
