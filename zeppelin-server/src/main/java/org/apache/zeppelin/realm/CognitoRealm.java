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
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
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

/**
 * A {@code Realm} implementation that uses the CognitoRealm to authenticate users.
 */
public class CognitoRealm extends AuthorizingRealm {
  private static final Logger LOG = LoggerFactory.getLogger(CognitoRealm.class);
  private final String userPoolId;
  private final String userPoolUrl;
  private final String userPoolClientId;
  private String name;
  private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();
  private final HttpClient httpClient;

  private final AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
          .standard()
          .withRegion("eu-central-1")
          .build();

  public CognitoRealm() {
      super();
      LOG.debug("Init CognitoRealm");
      httpClient = new HttpClient();
      name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
      this.userPoolUrl="TODO";
      this.userPoolClientId="TODO";
      this.userPoolId="TODO";
  }

  @Override
  public void onInit(){
    super.onInit();
    LOG.info("Try to call: " + userPoolUrl);
  }

  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    return null;
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    System.out.println("This is in the doGetAuthenticationInfo");
    UsernamePasswordToken userInfo = (UsernamePasswordToken) token;
    String userName = userInfo.getUsername();
    char[] password = userInfo.getPassword();
    LOG.info("username: " + userInfo.getUsername());
    LOG.info("password: " + userInfo.getPassword().toString());

//        AuthenticationResultType authenticationResult = null;
    final Map<String, String> authParams = new HashMap<>();
    authParams.put("USERNAME", userName);
    authParams.put("PASSWORD", String.valueOf(password));
    authParams.put("SECRET_HASH", calculateHash(userName));

      AdminInitiateAuthResult authResponse = this.initiateAuthRequest(authParams);
      AuthenticationResultType authenticationResult = authResponse.getAuthenticationResult();
      System.out.println(authenticationResult.getAccessToken());
      System.out.println(authenticationResult.getIdToken());
      System.out.println(authenticationResult.getRefreshToken());
      System.out.println("----------------------------");

    // AdminRespondToAuthChallenge
    String challengeName = authResponse.getChallengeName();
    if (StringUtils.isNotBlank(challengeName)) {
        if (ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(challengeName)) {
            LOG.info("In NEW_PASSWORD_REQUIRED Challenge!");
            // client code should be present in zeppelin to handle new password request, new password needs to be passed to this method and passed as response
            // to Cognito for the challenge

            final Map<String, String> challengeResponses = new HashMap<>();
            challengeResponses.put("USERNAME", userName);
            challengeResponses.put("PASSWORD", String.valueOf(password));
            challengeResponses.put("NEW_PASSWORD", "TODO-NEEDS TO BE MIN 16 chars!2#");
            challengeResponses.put("SECRET_HASH", calculateHash(userName));

            AdminRespondToAuthChallengeRequest respondToChallengeRequest = new AdminRespondToAuthChallengeRequest();

          respondToChallengeRequest
                  .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                  .withChallengeResponses(challengeResponses)
                  .withClientId(userPoolClientId)
                  .withUserPoolId(userPoolId)
                  .withSession(authResponse.getSession());

            AdminRespondToAuthChallengeResult challengeResponse = cognitoIdentityProvider.adminRespondToAuthChallenge(respondToChallengeRequest);
            System.out.println(challengeResponse);

            AuthenticationResultType authResult = challengeResponse.getAuthenticationResult();
            System.out.println(authResult);
            System.out.println(authResult.getAccessToken());
            System.out.println(authResult.getIdToken());
            System.out.println(authResult.getRefreshToken());

        }
    } else {
        LOG.info("No challenge to respond to!");
    }
        return null;
  }

    private String calculateHash(String userName) {
        return SecretHashCalculator.calculate(userPoolClientId, "TODO", userName);
    }

    private AdminInitiateAuthResult initiateAuthRequest(Map<String, String> authParams){
    final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
    authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
            .withClientId(userPoolClientId)
            .withUserPoolId(userPoolId)
            .withAuthParameters(authParams);

    // AdminInitiateAuth
    return cognitoIdentityProvider.adminInitiateAuth(authRequest);
  }

  protected ListUsersResult getUserList(){
    ListUsersRequest listUsersRequest = new ListUsersRequest();
    listUsersRequest.setUserPoolId(userPoolId);
    return cognitoIdentityProvider.listUsers(listUsersRequest);
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

  /**
   * Send to ZeppelinHub a login request based on the request body which is a JSON that contains 2
   * fields "login" and "password".
   *
   * @param requestBody JSON string of ZeppelinHub payload.
   * @return Account object with login, name (if set in ZeppelinHub), and mail.
   * @throws AuthenticationException if fail to login.
   */
  protected User authenticateUser(String requestBody) {
    return null;
  }

  /**
   * Helper class that will be use to fromJson ZeppelinHub response.
   */
  protected static class User implements JsonSerializable {
    private static final Gson gson = new Gson();
    public String login;
    public String email;
    public String name;

    public String toJson() {
      return gson.toJson(this);
    }

    public static ZeppelinHubRealm.User fromJson(String json) {
      return gson.fromJson(json, ZeppelinHubRealm.User.class);
    }
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

  public AWSCognitoIdentityProvider getCognitoIdentityProvider() {
    return cognitoIdentityProvider;
  }
}
