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


import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
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
import java.util.Arrays;
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
    private final HttpClient httpClient;
    private CognitoJwtVerifier cognitoJwtVerifier;
    private CognitoClientProvider cognito;
    public void setCognitoJwtVerifier(CognitoJwtVerifier cognitoJwtVerifier) throws MalformedURLException {
        LOG.info("setCognitoJwtVerifier: " + cognitoJwtVerifier.toString());
        cognitoJwtVerifier.setCognitoUserPoolUrl(userPoolUrl);
        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
        this.cognitoJwtVerifier = cognitoJwtVerifier;
    }


    public CognitoRealm() throws MalformedURLException {
        super();
        LOG.info("Init CognitoRealm");
        this.httpClient = new HttpClient();
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    @Override
    public void onInit() {
        super.onInit();
        cognito = new CognitoClientProvider(userPoolClientId, userPoolId);
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
        UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
        String username = userInfo.getUsername();
        String password = String.valueOf(userInfo.getPassword());
        if (username == null) {
            throw new AuthenticationException("Username cannot be empty!");
        }
        String hashedValue = SecretHashCalculator.calculate(userPoolClientId, userPoolClientSecret, username);
        SimpleAuthenticationInfo authenticationInfo = null;
        // AdminInitiateAuth
        final Map<String, String> authParams = cognito.buildAuthRequest(username, password, hashedValue);
        try {
            AdminInitiateAuthResult authResponse = cognito.initiateAuthRequest(authParams);
            // AdminRespondToAuthChallenge
            String challengeName = authResponse.getChallengeName();
            boolean isChallengePresent = StringUtils.isNotBlank(challengeName);
            if (!isChallengePresent) {
                AuthenticationResultType authResult = authResponse.getAuthenticationResult();
                String accessToken = authResult.getAccessToken();

                // parse and verify the jwt token
                try{
                    JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(accessToken);
                }catch(Exception ex){
                    LOG.info("Exception: " + ex.getMessage());
                }
            return new SimpleAuthenticationInfo(username, password, this.getName());
//                authenticationInfo = buildCognitoAuthenticationInfo(password, authResult.getIdToken());
//                return authenticationInfo;
            } else {
                LOG.info("Unexpected Cognito Challenge.");
                throw new AuthenticationException("Unexpected Cognito Challenge.");
            }
        } catch (Exception e) {
            LOG.info("An exception has occurred.", e);
            throw new RuntimeException("An exception has occurred.", e);
        }
//                AuthenticationResultType authenticationResult = authResponse.getAuthenticationResult();
//
//                String accessToken = authenticationResult.getAccessToken();
//
//                // parse and verify the jwt token
//                try{
//                    JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(accessToken);
//                }catch(Exception ex){
//                    LOG.info("Exception: " + ex.getMessage());
//                }
//            return new SimpleAuthenticationInfo(username, password, this.getName());
//        } else if(token instanceof CognitoToken) {
//            CognitoToken cognitoToken = (CognitoToken) token;
//            LOG.info("Should have a Cognito Token" + cognitoToken);
//            String username = "";
//            try{
//                cognitoJwtVerifier.setCognitoUserPoolId(userPoolId);
//                JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(cognitoToken.id_token);
//                username = claims.getStringClaim("cognito:username");
//            }catch(Exception ex){
//                LOG.info("Exception: " + ex.getMessage());
//            }
//            return new SimpleAuthenticationInfo(username, cognitoToken.id_token, this.getName());
//        }
//        return null;
    }

        private SimpleAuthenticationInfo buildCognitoAuthenticationInfo(String password, String idToken) {
            SimpleAuthenticationInfo authenticationInfo = null;
            try {
                JWTClaimsSet idTokenClaims = cognitoJwtVerifier.verifyJwt(idToken);
                LOG.info("TOKEN CLAIMS: " + idTokenClaims.getClaims());

                String[] rolesFromToken = idTokenClaims.getStringArrayClaim("cognito:groups");

                String realmName = this.getName();
//            SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
//            principalCollection.add(idTokenClaims.getClaim("cognito:username"), realmName);
//            principalCollection.addAll(list, realmName);
//            LOG.info("PRINCIPAL COLLECTION: " + principalCollection);
//            LOG.info("PRIMARY PRINCIPAL: " + principalCollection.getPrimaryPrincipal());

                CognitoUser cognitoUser = new CognitoUser(idTokenClaims.getStringClaim("cognito:username"),
                        idTokenClaims.getStringClaim("email"),
                        Arrays.asList(rolesFromToken));
//                cognitoUser.setUsername(idTokenClaims.getStringClaim("cognito:username"));
//                cognitoUser.setEmail(idTokenClaims.getStringClaim("email"));
//                cognitoUser.setRoles(Arrays.asList(rolesFromToken));


                SecurityUtils.getSubject().getSession().setAttribute("cognitoUser", cognitoUser);

//            authenticationInfo = new SimpleAuthenticationInfo(idTokenClaims.getClaim("cognito:username"), password, this.getName());
//            authenticationInfo = new SimpleAuthenticationInfo(principalCollection, password, realmName);
                authenticationInfo = new SimpleAuthenticationInfo(cognitoUser, password, realmName);
            } catch (Exception e) {
                LOG.info("Exception in normal auth: " + e.getMessage());
            }
            return authenticationInfo;
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

}
