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
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.util.*;
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
        cognitoJwtVerifier.setCognitoUserPoolId(userPoolId);
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
        String stringPrincipals = principals.toString();
        LOG.info("doGetAuthorizationInfo: " + stringPrincipals);

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        CognitoUser user = (CognitoUser) principals.getPrimaryPrincipal();

        LOG.info("USER EMAIL: " + user.getEmail());
        LOG.info("USERNAME: " + user.getUsername());

        authorizationInfo.addRoles(user.getRoles());
        for (String role : authorizationInfo.getRoles()) {
            LOG.info("ROLE: " + role);
        }

        authorizationInfo.addStringPermission("read");


//        String[] split = stringPrincipals.split(",");
//        for (String s : split) {
//            LOG.info("SPLIT STRING IS: " + s);
//        }
//        List principalsFromRealm = Arrays.asList(principals.fromRealm(this.name).toArray());
//        principalsFromRealm.stream().forEach(i -> LOG.info("Principal item: " + i));
        LOG.info("End of authorization info");
//        principalsFromRealm.stream().map(i -> authorizationInfo.addRole(i))
//        for (Object item : principalsFromRealm) {
//    }
        return authorizationInfo;
    }

    @Override
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
        String userName = userInfo.getUsername();
        String password = String.valueOf(userInfo.getPassword());

        if (userName == null) {
            throw new AuthenticationException("Username cannot be empty!");
        }

        SimpleAuthenticationInfo authenticationInfo = null;

        String hashedValue = SecretHashCalculator.calculate(userPoolClientId, userPoolClientSecret, userName);

        final Map<String, String> authParams = buildAuthRequest(userName, password, hashedValue);
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

            CognitoUser cognitoUser = new CognitoUser();
            cognitoUser.setUsername(idTokenClaims.getStringClaim("cognito:username"));
            cognitoUser.setEmail(idTokenClaims.getStringClaim("email"));
            cognitoUser.setRoles(Arrays.asList(rolesFromToken));


            SecurityUtils.getSubject().getSession().setAttribute("cognitoUser", cognitoUser);

//            authenticationInfo = new SimpleAuthenticationInfo(idTokenClaims.getClaim("cognito:username"), password, this.getName());
//            authenticationInfo = new SimpleAuthenticationInfo(principalCollection, password, realmName);
            authenticationInfo = new SimpleAuthenticationInfo(cognitoUser, password, realmName);
        } catch (Exception e) {
            LOG.info("Exception in normal auth: " + e.getMessage());
        }
        return authenticationInfo;
    }

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


    public String getUserPoolId() {
        return userPoolId;
    }

    public String getUserPoolUrl() {
        return userPoolUrl;
    }

    public String getUserPoolClientId() {
        return userPoolClientId;
    }

    public String getUserPoolClientSecret() {
        return userPoolClientSecret;
    }

}
