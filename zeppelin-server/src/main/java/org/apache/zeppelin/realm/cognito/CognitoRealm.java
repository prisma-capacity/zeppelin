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


import com.amazonaws.services.cognitoidp.model.*;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private final String name;
    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();
    private CognitoClient cognitoClient;
    private CognitoJwtVerifier cognitoJwtVerifier;
    private final Map<String, String> roles = new HashMap<>();

    public CognitoRealm() {
        super();
        LOG.info("Init CognitoRealm");
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    @Override
    public void onInit() {
        super.onInit();
        this.cognitoClient = new CognitoClient(userPoolClientId, userPoolId, new CognitoClientProvider());
        this.cognitoJwtVerifier = new CognitoJwtVerifier(userPoolClientId, userPoolId);
    }

    public Map<String, String> getRolesList() {
        List<String> cognitoGroups = cognitoClient.getCognitoGroups();
        Map<String, String> roles = new HashMap<>();
        for (String entry : cognitoGroups) {
            roles.put(entry, "*");
        }
        return roles;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        LOG.info("In doGetAuthorizationInfo");

        LOG.info("principals : " + principals.toString());

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        CognitoUser user = (CognitoUser) principals.getPrimaryPrincipal();

        LOG.info("user : " + user.toString());
        authorizationInfo.addRoles(user.getRoles());
        return authorizationInfo;
    }

    @Override
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        LOG.info("In doGetAuthenticationInfo");

        UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
        String userName = userInfo.getUsername();
        String password = String.valueOf(userInfo.getPassword());

        if (userName == null) {
            LOG.info("In NULL USERNAME");
            throw new AuthenticationException("Username cannot be empty!");
        }

        SimpleAuthenticationInfo authenticationInfo = null;
        CognitoUser cognitoUser = new CognitoUser();

        String hashedValue = SecretHashCalculator.calculate(userPoolClientId, userPoolClientSecret, userName);

        final Map<String, String> authParams = cognitoClient.buildAuthRequest(userName, password, hashedValue);
        try {
            AdminInitiateAuthResult initiateAuthResult = cognitoClient.initiateAuth(authParams);
//            InitiateAuthResult initiateAuthResult2 = cognitoClient.initiateAuth2(authParams);

            String challengeName = initiateAuthResult.getChallengeName();
            boolean isChallengePresent = StringUtils.isNotBlank(challengeName);
            AuthenticationResultType authenticationResult = initiateAuthResult.getAuthenticationResult();
            LOG.info("AUTHENTICATION RESULT: " + authenticationResult);
            LOG.info("SESSION: " + initiateAuthResult.getSession());

            if (!isChallengePresent) {
                authenticationInfo = buildCognitoAuthenticationInfo(password, authenticationResult.getIdToken(), cognitoUser);
                return authenticationInfo;
            } else if (ChallengeNameType.MFA_SETUP.name().equals(challengeName)) {
                LOG.info("MFA_SETUP CHALLENGE PARAMS: " + initiateAuthResult.getChallengeParameters());

                AssociateSoftwareTokenRequest associateTokenRequest = new AssociateSoftwareTokenRequest();
                associateTokenRequest.setSession(initiateAuthResult.getSession());
                AssociateSoftwareTokenResult associateSoftwareTokenResult = cognitoClient.getCognito().associateSoftwareToken(associateTokenRequest);
                String secretCode = associateSoftwareTokenResult.getSecretCode();
                String associateSession = associateSoftwareTokenResult.getSession();
                LOG.info("ASSOCIATE TOKEN RESULT SECRET CODE: " + secretCode);
                LOG.info("ASSOCIATE TOKEN RESULT SESSION: " + associateSession);

                // TODO Display the returned code to the UI as a string code or QR code for the user to enter/scan in an Authenticator app.
                // Once user hits OK, then they can use the 6 digit token
                // MFA token field should be presented and they should provide a 6 digit token
                // new endpoint is hit and verify totp token process starts

                // NOte: FORBIDDEN WAS NOT SHOWN!
//                throw new AuthenticationException("My exception as trial.");

//                authenticationInfo = buildCognitoAuthenticationInfo(password, "", cognitoUser);

//                LOG.info("BEFORE MFA TOKEN VERIFY RESULT");
//                String oneTimeToken = "428144";
//
//                VerifySoftwareTokenResult tokenResult = cognitoClient.verifySoftwareTokenForAppMFA(
//                        "", oneTimeToken);
//                if(tokenResult != null){
//                    LOG.info("MFA TOKEN VERIFY RESULT: " + tokenResult.getStatus());
//                }else{
//                    LOG.info("MFA VERIFICATION FAILED");
//                }

                cognitoUser.setMfaSetup(true); // TODO Maybe there is no need for that
                cognitoUser.setRoles(Collections.singletonList("admin"));
                cognitoUser.setUsername(userName);
                cognitoUser.setEmail(userName); // TODO: authenticationResult is NULL .getIdToken() verification fails ???
                cognitoUser.setCognitoMfaToken(secretCode);
                cognitoUser.setAdminInitiateAuthResult(initiateAuthResult);
                cognitoUser.setAssociateSession(associateSession);

                SecurityUtils.getSubject().getSession().setAttribute("cognitoUser", cognitoUser);
                authenticationInfo = new SimpleAuthenticationInfo(cognitoUser, password, this.getName());
//                authenticationInfo = buildCognitoAuthenticationInfo(password, authenticationResult.getIdToken(), cognitoUser);
                return authenticationInfo;
//                throw new NullPointerException("My null ex");
            } else if (ChallengeNameType.SOFTWARE_TOKEN_MFA.name().equals(challengeName)) {
                LOG.info("SW_TOKEN_MFA CHALLENGE PARAMS: " + initiateAuthResult.getChallengeParameters());
                LOG.info("CHALLENGE IS SW_TOKEN_MFA: " + challengeName);

//                // TODO: verify if the session if the correct one
//                VerifySoftwareTokenResult tokenResult = cognitoClient.verifySoftwareTokenForAppMFA(initiateAuthResult.getSession(), "651589");
//                LOG.info("MFA TOKEN VERIF RESULT: "+ tokenResult.getStatus());

                //                final Map<String, String> challengeResponses = cognitoClient.buildAuthRequest(userName, password, hashedValue);
//                challengeResponses.put("MFA_SETUP", "SomethingForMFASetup");
//                LOG.info("BUILT CHALLENGE RESPONSE: "+ challengeResponses);

//                AdminRespondToAuthChallengeResult respondToMfaSetupResult = cognitoClient.respondToAuthChallenge(ChallengeNameType.MFA_SETUP, initiateAuthResult, challengeResponses);
//                RespondToAuthChallengeResult respondToMfaSetupResult = cognitoClient.respondToAuthChallenge(ChallengeNameType.MFA_SETUP, initiateAuthResult, challengeResponses);
//                LOG.info("CHALLENGE RESPONSE - MFA_SETUP: " + respondToMfaSetupResult);

//                AssociateSoftwareTokenRequest associateTokenRequest = new AssociateSoftwareTokenRequest();
//                associateTokenRequest.setSession(initiateAuthResult.getSession());
//                AssociateSoftwareTokenResult associateSoftwareTokenResult = cognitoClient.getCognito().associateSoftwareToken(associateTokenRequest);
//                String secretCode = associateSoftwareTokenResult.getSecretCode();
//                String associateSession = associateSoftwareTokenResult.getSession();
//                LOG.info("ASSOCIATE TOKEN RESULT SECRET CODE: " + secretCode);
//                LOG.info("ASSOCIATE TOKEN RESULT SESSION: " + associateSession);

                // TODO: rename flags
                cognitoUser.setRequiresMfa(true);
                cognitoUser.setMfaSetup(false);
                cognitoUser.setRoles(Collections.singletonList("admin"));
                cognitoUser.setUsername(userName);
                cognitoUser.setEmail(userName); // TODO: authenticationResult is NULL .getIdToken() verification fails ???
//                cognitoUser.setCognitoMfaToken(secretCode);
                cognitoUser.setAdminInitiateAuthResult(initiateAuthResult);
//                cognitoUser.setInitiateAuthResult(initiateAuthResult2);
//                cognitoUser.setAssociateSession(associateSession);

                SecurityUtils.getSubject().getSession().setAttribute("cognitoUser", cognitoUser);
                authenticationInfo = new SimpleAuthenticationInfo(cognitoUser, password, this.getName());
                return authenticationInfo;
            } else {
                LOG.error("Unexpected Cognito Challenge.");
                LOG.info("CHALLENGE IS OTHER: " + challengeName);
                throw new AuthenticationException("Unexpected Cognito Challenge.");
            }
        } catch (Exception e) {
//            LOG.error("An exception has occurred.", e);
            throw new AuthenticationException("An exception has occurred.", e);
        }
    }

    private SimpleAuthenticationInfo buildCognitoAuthenticationInfo(String password, String idToken, CognitoUser cognitoUser) {
        SimpleAuthenticationInfo authenticationInfo = null;
        try {
            JWTClaimsSet idTokenClaims = cognitoJwtVerifier.verifyJwt(idToken);
//            LOG.info("TOKEN CLAIMS: " + idTokenClaims.getClaims());

            cognitoUser.setUsername(idTokenClaims.getStringClaim("cognito:username"));
            cognitoUser.setEmail(idTokenClaims.getStringClaim("email"));

            if (!idTokenClaims.getClaims().containsKey("cognito:groups")) {
                cognitoUser.setRoles(Collections.singletonList("prisma"));
            } else {
                String[] rolesFromToken = idTokenClaims.getStringArrayClaim("cognito:groups");
                cognitoUser.setRoles(Arrays.asList(rolesFromToken));
            }

            SecurityUtils.getSubject().getSession().setAttribute("cognitoUser", cognitoUser);

            authenticationInfo = new SimpleAuthenticationInfo(cognitoUser, password, this.getName());
        } catch (Exception e) {
            LOG.info("Exception in normal auth: " + e.getMessage());
        }
        return authenticationInfo;
    }


//    private Map<String, String> buildAuthRequest(String username, String password, String hashedValue) {
//        final Map<String, String> authParams = new HashMap<>();
//        authParams.put("USERNAME", username);
//        authParams.put("PASSWORD", password);
//        authParams.put("SECRET_HASH", hashedValue);
//        return authParams;
//    }

//    private AdminInitiateAuthResult initiateAuth(Map<String, String> authParams) {
//        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
//        authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
//                .withClientId(userPoolClientId)
//                .withUserPoolId(userPoolId)
//                .withAuthParameters(authParams);
//        return cognito.adminInitiateAuth(authRequest);
//    }

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


//    public void setCognitoClientProvider(CognitoClientProvider cognitoClientProvider) {
//        this.cognitoClientProvider = cognitoClientProvider;
//    }

//    public void setCognitoClientProvider(CognitoClientProvider cognitoClientProvider) {
//        this.cognitoClientProvider = cognitoClientProvider;
//        if (cognitoClientProvider != null) {
//            this.cognito = this.cognitoClientProvider.getCognito();
//        }
//    }
//
//    public void setCognitoJwtVerifier(CognitoJwtVerifier cognitoJwtVerifier) {

//        cognitoJwtVerifier.setCognitoUserPoolUrl(userPoolUrl);
//        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
//        cognitoJwtVerifier.setCognitoUserPoolId(userPoolId);
//        this.cognitoJwtVerifier = cognitoJwtVerifier;
//    }
