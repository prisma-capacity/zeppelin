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

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
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
    private static final String JSON_CONTENT_TYPE = "application/json";
    private static final String UTF_8_ENCODING = "UTF-8";
    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();
    private static final String USER_SESSION_HEADER = "X-session";

    private static final String USER_LOGIN_API_ENDPOINT = "api/v1/users/login";
    private static final String DEFAULT_COGNITO_URL = "https://www.testing.com";

    private final HttpClient httpClient;

    private String userPoolId = "user-pool-id";
    private String userPoolUrl = "user-pool-url";
    private String region = "eu-central-1";
    private String userPoolClientId = "user-pool-client-id";
    private final AWSCognitoIdentityProvider cognito;
    private String name;

    public CognitoRealm() {
        super();
        LOG.debug("Init CognitoRealm");
        httpClient = new HttpClient();
        name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
        this.cognito = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withCredentials(new AWSStaticCredentialsProvider(new AnonymousAWSCredentials()))
                .withRegion(region)
                .build();
    }

    protected void onInit() {
        super.onInit();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("This is in the doGetAuthenticationInfo");
        UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
        String userName = userInfo.getUsername();
        char[] password = userInfo.getPassword();
        LOG.info("username: " + userInfo.getUsername());
        LOG.info("password: " + userInfo.getPassword());

//        AuthenticationResultType authenticationResult = null;
        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", userName);
        authParams.put("PASSWORD", String.valueOf(password));

        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .withClientId(userPoolClientId)
                .withUserPoolId(userPoolId)
                .withAuthParameters(authParams);

        // AdminInitiateAuth
        AdminInitiateAuthResult authResponse = cognito.adminInitiateAuth(authRequest);

        // AdminRespondToAuthChallenge
        String challengeName = authResponse.getChallengeName();
        if (StringUtils.isNotBlank(challengeName)) {
            // TODO
            if (ChallengeNameType.NEW_PASSWORD_REQUIRED.toString().equals(challengeName)) {
                LOG.info("Decide what to do in this flow. NOT FINISHED!");
            }
        } else {
            LOG.info("In else, not finished yet!");
        }
        return null;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("This is in the doGetAuthorizationInfo");
        return null;
    }

    /**
     * Create a JSON String that represent login payload.
     *
     * Payload will look like:
     * {@code
     *  {
     *   'login': 'userLogin',
     *   'password': 'userpassword'
     *  }
     * }
     * @param login
     * @param pwd
     * @return
     */
//  protected String createLoginPayload(String login, char[] pwd) {
//    StringBuilder sb = new StringBuilder("{\"login\":\"");
//    return sb.append(login).append("\", \"password\":\"").append(pwd).append("\"}").toString();
//  }

    /**
     * Helper class that will be use to fromJson ZeppelinHub response.
     */
//  protected static class User implements JsonSerializable {
//    private static final Gson gson = new Gson();
//    public String login;
//    public String email;
//    public String name;
//
//    public String toJson() {
//      return gson.toJson(this);
//    }
//
//    public static User fromJson(String json) {
//      return gson.fromJson(json, User.class);
//    }
//  }

//  public void onLoginSuccess(String username, String session) {
//    UserSessionContainer.instance.setSession(username, session);
//
//    HashSet<String> userAndRoles = new HashSet<>();
//    userAndRoles.add(username);
//    ServiceContext context = new ServiceContext(
//        new org.apache.zeppelin.user.AuthenticationInfo(username), userAndRoles);
//    try {
//      // This can failed to get NotebookServer instance with very rare cases
//      NotebookServer.getInstance().broadcastReloadedNoteList(null, context);
//    } catch (IOException e) {
//      LOG.error("Fail to broadcastReloadedNoteList", e);
//    }
//
//    ZeppelinhubUtils.userLoginRoutine(username);
//  }

//  @Override
//  public void onLogout(PrincipalCollection principals) {
//    ZeppelinhubUtils.userLogoutRoutine((String) principals.getPrimaryPrincipal());
//  }
    public String getUserPoolClientId() {
        return userPoolClientId;
    }

    public String getUserPoolUrl() {
        return userPoolUrl;
    }

    public String getUserPoolId() {
        return userPoolId;
    }

    /**
     * Perform a Simple URL check by using {@code URI(url).toURL()}.
     * If the url is not valid, the try-catch condition will catch the exceptions and return false,
     * otherwise true will be returned.
     *
     * @param url
     * @return
     */
    protected boolean isUserPoolUrlValid(String url) {
        boolean valid;
        try {
            new URI(url).toURL();
            valid = true;
        } catch (URISyntaxException | MalformedURLException e) {
            LOG.error("Cognito url is not valid.", e);
            valid = false;
        }
        return valid;
    }

    public void setUserPoolId(String userPoolId) {
        this.userPoolId = userPoolId;
    }

    public void setUserPoolUrl(String url) {
        if (StringUtils.isBlank(url)) {
            LOG.warn("Cognito url is empty, setting up default url {}", DEFAULT_COGNITO_URL);
            userPoolUrl = DEFAULT_COGNITO_URL;
        } else {
            userPoolUrl = (isUserPoolUrlValid(url) ? url : DEFAULT_COGNITO_URL);
            LOG.info("Setting up Cognito url to {}", userPoolUrl);
        }
    }

    public void setUserPoolClientId(String userPoolClientId) {
        this.userPoolClientId = userPoolClientId;
    }
}
