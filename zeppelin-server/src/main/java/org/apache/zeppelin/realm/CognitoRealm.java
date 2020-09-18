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

import com.google.common.base.Joiner;
import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.zeppelin.common.JsonSerializable;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.notebook.repo.zeppelinhub.model.UserSessionContainer;
import org.apache.zeppelin.notebook.repo.zeppelinhub.websocket.utils.ZeppelinhubUtils;
import org.apache.zeppelin.service.ServiceContext;
import org.apache.zeppelin.socket.NotebookServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@code Realm} implementation that uses the CognitoRealm to authenticate users.
 *
 */
public class CognitoRealm extends AuthorizingRealm {
  private static final Logger LOG = LoggerFactory.getLogger(CognitoRealm.class);
  private static final String JSON_CONTENT_TYPE = "application/json";
  private static final String UTF_8_ENCODING = "UTF-8";
  private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();

  private final HttpClient httpClient;
  private String userPoolId;
  private String userPoolUrl;
  private String userPoolClientId;
  private String name;
  private IniRealm iniRealm;
  private Ini ini;
  private final ZeppelinConfiguration conf;

  @Inject
  public CognitoRealm(ZeppelinConfiguration conf){
    super();
    LOG.debug("Init CognitoRealm");
    httpClient = new HttpClient();
    name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    // String projectDir = System.getProperty("user.dir");
    this.conf = conf;
    this.iniRealm = new IniRealm(conf.getShiroPath());
    this.ini = iniRealm.getIni();
    this.userPoolClientId = ini.getSectionProperty("main", "cognitoRealm.userPoolClientId");
    this.userPoolId = ini.getSectionProperty("main", "cognitoRealm.userPoolId");
    this.userPoolUrl = ini.getSectionProperty("main", "cognitoRealm.userPoolUrl");
  }

  protected void onInit() {
    super.onInit();
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    System.out.println("This is in the doGetAuthenticationInfo");
    return null;
  }

  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
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

}
