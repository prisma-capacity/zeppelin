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
package org.apache.zeppelin.rest;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.zeppelin.annotation.ZeppelinApi;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.notebook.AuthorizationService;
import org.apache.zeppelin.notebook.Notebook;
import org.apache.zeppelin.realm.cognito.CognitoJwtVerifier;
import org.apache.zeppelin.realm.cognito.CognitoRealm;
import org.apache.zeppelin.realm.cognito.CognitoToken;
import org.apache.zeppelin.realm.jwt.JWTAuthenticationToken;
import org.apache.zeppelin.realm.jwt.KnoxJwtRealm;
import org.apache.zeppelin.realm.kerberos.KerberosRealm;
import org.apache.zeppelin.realm.kerberos.KerberosToken;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.service.AuthenticationService;
import org.apache.zeppelin.ticket.TicketContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created for org.apache.zeppelin.rest.message.
 */
@Path("/login")
@Produces("application/json")
@Singleton
public class LoginRestApi {
  private static final Logger LOG = LoggerFactory.getLogger(LoginRestApi.class);
  private static final Gson GSON = new Gson();
  private final ZeppelinConfiguration zConf;

  private final AuthenticationService authenticationService;
  private final AuthorizationService authorizationService;

  @Inject
  public LoginRestApi(Notebook notebook,
                      AuthenticationService authenticationService,
                      AuthorizationService authorizationService) {
    this.zConf = notebook.getConf();
    this.authenticationService = authenticationService;
    this.authorizationService = authorizationService;
  }

  @GET
  @ZeppelinApi
  public Response getLogin(@Context HttpHeaders headers, @QueryParam("code") String code) {
    JsonResponse<Map<String, String>> response = null;
    CognitoRealm cognitoRealm = getCognitoRealm();
    if(cognitoRealm != null && code != null){
      return loginWithCognito(code, cognitoRealm);
    }
    if (isKnoxSSOEnabled()) {
      KnoxJwtRealm knoxJwtRealm = getJTWRealm();
      Cookie cookie = headers.getCookies().get(knoxJwtRealm.getCookieName());
      if (cookie != null && cookie.getValue() != null) {
        Subject currentUser = SecurityUtils.getSubject();
        JWTAuthenticationToken token = new JWTAuthenticationToken(null, cookie.getValue());
        try {
          String name = knoxJwtRealm.getName(token);
          if (!currentUser.isAuthenticated() || !currentUser.getPrincipal().equals(name)) {
            response = proceedToLogin(currentUser, token);
          }
        } catch (ParseException e) {
          LOG.error("ParseException in LoginRestApi: ", e);
        }
      }
      if (response == null) {
        Map<String, String> data = new HashMap<>();
        data.put("redirectURL", constructKnoxUrl(knoxJwtRealm, knoxJwtRealm.getLogin()));
        response = new JsonResponse<>(Status.OK, "", data);
      }
      return response.build();
    }

    KerberosRealm kerberosRealm = getKerberosRealm();
    if (null != kerberosRealm) {
      try {
        Map<String, Cookie> cookies = headers.getCookies();
        KerberosToken kerberosToken = KerberosRealm.getKerberosTokenFromCookies(cookies);
        if (null != kerberosToken) {
          Subject currentUser = SecurityUtils.getSubject();
          String name = (String) kerberosToken.getPrincipal();
          if (!currentUser.isAuthenticated() || !currentUser.getPrincipal().equals(name)) {
            response = proceedToLogin(currentUser, kerberosToken);
          }
        }
        if (null == response) {
          LOG.warn("No Kerberos token received");
          response = new JsonResponse<>(Status.UNAUTHORIZED, "", null);
        }
        return response.build();
      } catch (AuthenticationException e){
        LOG.error("Error in Login", e);
      }
    }
    return new JsonResponse<>(Status.METHOD_NOT_ALLOWED).build();
  }

  private Response loginWithCognito(String code, CognitoRealm cognitoRealm){
    JsonResponse<Map<String, String>> response = null;
    cognitoRealm.onInit();
    String userPoolId = cognitoRealm.getUserPoolId();
    String userPoolUrl = cognitoRealm.getUserPoolUrl();
    String userPoolClientId = cognitoRealm.getUserPoolClientId();
    String clientSecret = cognitoRealm.getUserPoolClientSecret();
    String auth = Base64.getEncoder().encodeToString((userPoolClientId + ":" + clientSecret).getBytes());
    HttpClient httpClient = new HttpClient();
    PostMethod post = new PostMethod(userPoolUrl + "oauth2/token");
    post.addRequestHeader("Content-type", "application/x-www-form-urlencoded");
    post.addRequestHeader("Authorization", "Basic " + auth);
    post.setParameter("grant_type", "authorization_code");
    post.setParameter("client_id", userPoolClientId);
    post.setParameter("code", code);
    post.setParameter("redirect_uri", "http://localhost:8080/api/login");
    try {
      int status = httpClient.executeMethod(post);
      if(status == HttpStatus.SC_OK){
        String postResponse = post.getResponseBodyAsString();
        CognitoToken token = CognitoToken.fromJson(postResponse);
        CognitoJwtVerifier cognitoJwtVerifier = new CognitoJwtVerifier();
        cognitoJwtVerifier.setCognitoUserPoolUrl("https://cognito-idp.eu-central-1.amazonaws.com/" + userPoolId);
        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
        JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(token.id_token);
        String username = (String) claims.getClaim("cognito:username");
        PrincipalCollection principals = new SimplePrincipalCollection(username, "CognitoRealm");
        Subject subject = new Subject.Builder().principals(principals).buildSubject();
        response = proceedToLogin(subject, token);
        return response.build();
      }
    } catch (HttpException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    } catch (BadJOSEException e) {
      e.printStackTrace();
    }
    return new JsonResponse<>(Status.METHOD_NOT_ALLOWED).build();
  }

  private KerberosRealm getKerberosRealm() {
    Collection<Realm> realmsList = authenticationService.getRealmsList();
    if (realmsList != null) {
      for (Realm realm : realmsList) {
        String name = realm.getClass().getName();

        LOG.debug("RealmClass.getName: {}", name);

        if (name.equals("org.apache.zeppelin.realm.kerberos.KerberosRealm")) {
          return (KerberosRealm) realm;
        }
      }
    }
    return null;
  }

  private KnoxJwtRealm getJTWRealm() {
    Collection<Realm> realmsList = authenticationService.getRealmsList();
    if (realmsList != null) {
      for (Realm realm : realmsList) {
        if (realm instanceof KnoxJwtRealm) {
          return (KnoxJwtRealm) realm;
        }
      }
    }
    return null;
  }

  private CognitoRealm getCognitoRealm() {
    Collection<Realm> realmsList = authenticationService.getRealmsList();
    if (realmsList != null) {
      for (Realm realm : realmsList) {
        if (realm instanceof CognitoRealm) {
          return (CognitoRealm) realm;
        }
      }
    }
    return null;
  }

  private boolean isKnoxSSOEnabled() {
    Collection<Realm> realmsList = authenticationService.getRealmsList();
    if (realmsList != null) {
      for (Realm realm : realmsList) {
        if (realm instanceof KnoxJwtRealm) {
          return true;
        }
      }
    }
    return false;
  }

  private JsonResponse<Map<String, String>> proceedToLogin(Subject currentUser, AuthenticationToken token) {
    JsonResponse<Map<String, String>> response = null;
    try {
      logoutCurrentUser();
      currentUser.getSession(true);
      currentUser.login(token);

      Set<String> roles = authenticationService.getAssociatedRoles();
      String principal = authenticationService.getPrincipal();
      String ticket = "anonymous".equals(principal) ? "anonymous" : TicketContainer.instance.getTicket(principal);

      Map<String, String> data = new HashMap<>();
      data.put("principal", principal);
      data.put("roles", GSON.toJson(roles));
      data.put("ticket", ticket);

      response = new JsonResponse<>(Status.OK, "", data);
      // if no exception, that's it, we're done!

      // set roles for user in NotebookAuthorization module
      authorizationService.setRoles(principal, roles);
    } catch (AuthenticationException uae) {
      // username wasn't in the system, show them an error message?
      // password didn't match, try again?
      // account for that username is locked - can't login.  Show them a message?
      // unexpected condition - error?
      LOG.error("Exception in login: ", uae);
    }
    return response;
  }

  /**
   * Post Login
   * Returns userName & password
   * for anonymous access, username is always anonymous.
   * After getting this ticket, access through websockets become safe
   *
   * @return 200 response
   */
  @POST
  @ZeppelinApi
  public Response postLogin(@FormParam("userName") String userName,
      @FormParam("password") String password) {
    LOG.info("postLogin/ start");
    LOG.info("userName: {}", userName);
    // ticket set to anonymous for anonymous user. Simplify testing.
    Subject currentUser = SecurityUtils.getSubject();
    if (currentUser.isAuthenticated()) {
      LOG.info("postLogin/ in already auth branch");
      currentUser.logout();
    }
    LOG.info("currentUser: {}", currentUser.getPrincipal());
    JsonResponse<Map<String, String>> response = null;
    if (!currentUser.isAuthenticated()) {
      LOG.info("postLogin/ in not auth branch");

      LOG.info("postLogin/username: {}", userName);
      LOG.info("postLogin/password: {}", password);

      AuthenticationToken token = null;
      token = new UsernamePasswordToken(userName, password);
      response = proceedToLogin(currentUser, token);
    }

    if (response == null) {
      LOG.info("postLogin/ in response is null branch");
      response = new JsonResponse<>(Response.Status.FORBIDDEN, "", null);
    }

    LOG.info(response.toString());
    return response.build();
  }

  @POST
  @Path("logout")
  @ZeppelinApi
  public Response logout() {
    logoutCurrentUser();
    Status status;
    Map<String, String> data = new HashMap<>();
    if (zConf.isAuthorizationHeaderClear()) {
      status = Status.UNAUTHORIZED;
      data.put("clearAuthorizationHeader", "true");
    } else {
      status = Status.FORBIDDEN;
      data.put("clearAuthorizationHeader", "false");
    }
    if (isKnoxSSOEnabled()) {
      KnoxJwtRealm knoxJwtRealm = getJTWRealm();
      data.put("redirectURL", constructKnoxUrl(knoxJwtRealm, knoxJwtRealm.getLogout()));
      data.put("isLogoutAPI", knoxJwtRealm.getLogoutAPI().toString());
    }
    JsonResponse<Map<String, String>> response = new JsonResponse<>(status, "", data);
    LOG.info(response.toString());
    return response.build();
  }

  private String constructKnoxUrl(KnoxJwtRealm knoxJwtRealm, String path) {
    StringBuilder redirectURL = new StringBuilder(knoxJwtRealm.getProviderUrl());
    redirectURL.append(path);
    if (knoxJwtRealm.getRedirectParam() != null) {
      redirectURL.append("?").append(knoxJwtRealm.getRedirectParam()).append("=");
    }
    return redirectURL.toString();
  }

  private void logoutCurrentUser() {
    Subject currentUser = SecurityUtils.getSubject();
    TicketContainer.instance.removeTicket(authenticationService.getPrincipal());
    currentUser.getSession().stop();
    currentUser.logout();
  }
}
