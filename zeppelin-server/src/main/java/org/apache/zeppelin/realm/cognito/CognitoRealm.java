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
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
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
    private final HttpClient httpClient;
    private CognitoJwtVerifier cognitoJwtVerifier;
    private CognitoClientProvider cognitoClientProvider;
//    private AWSCognitoIdentityProvider cognito;
    private final Map<String, String> roles = new HashMap<>();
//    private Ini ini;
//
//    public Ini getIni() {
//        return this.ini;
//    }
//
//    public void setIni() {
//        IniRealm iniRealm = new IniRealm("classpath:shiro.ini");
//        this.ini = iniRealm.getIni();
//    }

//    public Map<String, String> getRoles() {
//        return this.roles;
//    }
//
//    public void setRoles() {
//        this.roles.putAll(this.ini.getSection("roles"));
//    }

    public Map<String, String> getRolesList() {
        List<String> cognitoGroups = cognitoClientProvider.getCognitoGroups();
        Map<String, String> roles = new HashMap<>();
        LOG.info("Roles: " + roles);
        for (String entry : cognitoGroups) {
            roles.put(entry, "*");
        }
        return roles;
    }

    public void setCognitoClientProvider(CognitoClientProvider cognitoClientProvider) {
        this.cognitoClientProvider = cognitoClientProvider;
//        if (cognitoClientProvider != null) {
//            this.cognito = this.cognitoClientProvider.getCognito();
//        }
    }

//    public void setCognitoJwtVerifier(CognitoJwtVerifier cognitoJwtVerifier) {
//        cognitoJwtVerifier.setCognitoUserPoolUrl(userPoolUrl);
//        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
//        this.cognitoJwtVerifier = cognitoJwtVerifier;
//
//    }


    public CognitoRealm() throws MalformedURLException {
        super();
        LOG.info("Init CognitoRealm");
        this.httpClient = new HttpClient();
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    @Override
    public void onInit() {
        LOG.info("Init Cognito Realm");
        super.onInit();
        this.cognitoClientProvider = new CognitoClientProvider(userPoolClientId, userPoolId);
        this.cognitoJwtVerifier = new CognitoJwtVerifier(userPoolClientId, userPoolId);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
//        String stringPrincipals = principals.toString();
//        LOG.info("doGetAuthorizationInfo: " + stringPrincipals);

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        CognitoUser user = (CognitoUser) principals.getPrimaryPrincipal();

//        LOG.info("USER EMAIL: " + user.getEmail());
//        LOG.info("USERNAME: " + user.getUsername());
//        LOG.info("ROLES: " + user.getRoles());

        authorizationInfo.addRoles(user.getRoles());
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

        final Map<String, String> authParams = cognitoClientProvider.buildAuthRequest(userName, password, hashedValue);
        try {
            AdminInitiateAuthResult authResponse = cognitoClientProvider.initiateAuth(authParams);

            String challengeName = authResponse.getChallengeName();
            boolean isChallengePresent = StringUtils.isNotBlank(challengeName);

            if (!isChallengePresent) {
                AuthenticationResultType authResult = authResponse.getAuthenticationResult();
                LOG.info("ID Token: " + authResult.getIdToken());
                authenticationInfo = buildCognitoAuthenticationInfo(password, authResult.getIdToken());

                return authenticationInfo;
            } else {
                LOG.error("Unexpected Cognito Challenge.");
                throw new AuthenticationException("Unexpected Cognito Challenge.");
            }
        } catch (Exception e) {
            LOG.error("An exception has occurred.", e);
            throw new AuthenticationException("An exception has occurred.", e);
        }
    }

    private SimpleAuthenticationInfo buildCognitoAuthenticationInfo(String password, String idToken) {
        SimpleAuthenticationInfo authenticationInfo = null;
        try {
            JWTClaimsSet idTokenClaims = cognitoJwtVerifier.verifyJwt(idToken);
//            LOG.info("TOKEN CLAIMS: " + idTokenClaims.getClaims());

            CognitoUser cognitoUser = new CognitoUser(idTokenClaims.getStringClaim("cognito:username"),
                    idTokenClaims.getStringClaim("email"));


            if (!idTokenClaims.getClaims().containsKey("cognito:groups")) {
                cognitoUser.setRoles(Collections.singletonList("prisma"));
            } else {
                String[] rolesFromToken = idTokenClaims.getStringArrayClaim("cognito:groups");
                cognitoUser.setRoles(Arrays.asList(rolesFromToken));
            }

            authenticationInfo = new SimpleAuthenticationInfo(cognitoUser, password, this.getName());

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
