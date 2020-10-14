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

import com.amazonaws.services.cognitoidp.model.VerifySoftwareTokenResult;
import com.google.gson.Gson;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.zeppelin.annotation.ZeppelinApi;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.notebook.AuthorizationService;
import org.apache.zeppelin.notebook.Notebook;
import org.apache.zeppelin.realm.cognito.*;
import org.apache.zeppelin.realm.jwt.JWTAuthenticationToken;
import org.apache.zeppelin.realm.jwt.KnoxJwtRealm;
import org.apache.zeppelin.realm.kerberos.KerberosRealm;
import org.apache.zeppelin.realm.kerberos.KerberosToken;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.service.AuthenticationService;
import org.apache.zeppelin.ticket.TicketContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;
import java.text.ParseException;
import java.util.*;

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
    private String userPoolId;
    private String userPoolClientId;

    public void setUserPoolId(String userPoolId) {
        this.userPoolId = userPoolId;
    }

    public void setUserPoolClientId(String userPoolClientId) {
        this.userPoolClientId = userPoolClientId;
    }

    public String getUserPoolId() {
        return userPoolId;
    }

    public String getUserPoolClientId() {
        return userPoolClientId;
    }

    private final AuthenticationService authenticationService;
    private final AuthorizationService authorizationService;
    private final CognitoClient cognitoClient;

    @Inject
    public LoginRestApi(Notebook notebook,
                        AuthenticationService authenticationService,
                        AuthorizationService authorizationService) {
        this.zConf = notebook.getConf();
        this.authenticationService = authenticationService;
        this.authorizationService = authorizationService;
        this.setUserPoolId("eu-central-1_w3ARxiaYL");
        this.setUserPoolClientId("2iptds6j50ekbh7tidapdd26bu");
        this.cognitoClient = new CognitoClient(userPoolClientId, userPoolId, new CognitoClientProvider());
        ;
    }

    // TODO CHECK IF THIS VERSION IS NEEDED OR REVERT
    @GET
    @ZeppelinApi
    public Response getLogin(@Context HttpHeaders headers, @QueryParam("code") String code) {
        JsonResponse<Map<String, String>> response = null;
        CognitoRealm cognitoRealm = getCognitoRealm();
        if (cognitoRealm != null && code != null) {
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
            } catch (AuthenticationException e) {
                LOG.error("Error in Login", e);
            }
        }
        return new JsonResponse<>(Status.METHOD_NOT_ALLOWED).build();
    }

    // TODO CHECK IF NEEDED
    private Response loginWithCognito(String code, CognitoRealm cognitoRealm) {
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
            if (status == HttpStatus.SC_OK) {
                String postResponse = post.getResponseBodyAsString();
                CognitoToken token = CognitoToken.fromJson(postResponse);
//        CognitoJwtVerifier cognitoJwtVerifier = new CognitoJwtVerifier();
//        cognitoJwtVerifier.setCognitoUserPoolUrl("https://cognito-idp.eu-central-1.amazonaws.com/" + userPoolId);
//        cognitoJwtVerifier.setCognitoUserPoolClientId(userPoolClientId);
//        JWTClaimsSet claims = cognitoJwtVerifier.verifyJwt(token.id_token);
//        String username = (String) claims.getClaim("cognito:username");
//        PrincipalCollection principals = new SimplePrincipalCollection(username, "CognitoRealm");
//        Subject subject = new Subject.Builder().principals(principals).buildSubject();
//        response = proceedToLogin(subject, token);
                return response.build();
            }
        } catch (HttpException e) {
            e.printStackTrace();
        } catch (IOException e) {
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

    // TODO CHECK IF NEEDED
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

            LOG.info("Before currentUser.login");
            currentUser.login(token);
            LOG.info("After currentUser.login");

            LOG.info("Before authenticationService.getAssociatedRoles");
            Set<String> roles = authenticationService.getAssociatedRoles();
            LOG.info("After authenticationService.getAssociatedRoles");

            LOG.info("Before authenticationService.getPrincipal");
            String principal = authenticationService.getPrincipal();
            LOG.info("After authenticationService.getPrincipal");

            String ticket = "anonymous".equals(principal) ? "anonymous" : TicketContainer.instance.getTicket(principal);

            Map<String, String> data = new HashMap<>();
            data.put("principal", principal);
            data.put("roles", GSON.toJson(roles));
            data.put("ticket", ticket);


            CognitoUser user = (CognitoUser) SecurityUtils.getSubject().getPrincipals().getPrimaryPrincipal();
            if (user != null) {
                data.put("cognitoSession", user.getCognitoMfaToken());
                data.put("isRequiresMfa", ((Boolean) user.isRequiresMfa()).toString());
            }

            LOG.info("In the proceedToLogin:  " + data);
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
                              @FormParam("password") String password
    ) {

        LOG.info("In postLogin - start");
        // ticket set to anonymous for anonymous user. Simplify testing.
        Subject currentUser = SecurityUtils.getSubject();
        if (currentUser.isAuthenticated()) {
            LOG.info("is auth - we make logout");
            currentUser.logout();
        }
        JsonResponse<Map<String, String>> response = null;
        if (!currentUser.isAuthenticated()) {
            LOG.info("not auth - we proceed with login");
            AuthenticationToken token = null;
            token = new UsernamePasswordToken(userName, password);
            LOG.info("currentUser: " + currentUser);
            response = proceedToLogin(currentUser, token);

            LOG.info("response: " + response);
            CognitoUser user = (CognitoUser) SecurityUtils.getSubject().getPrincipals().getPrimaryPrincipal();
            if (user != null) {
                LOG.info("user is set:");
                LOG.info("isMfaSetup: " + user.isMfaSetup());
                LOG.info("isRequiresMfa: " + user.isRequiresMfa());
                // redirect / load a page
            } else {
                LOG.info("user is NULL");
            }
        }

        if (response == null) {
            response = new JsonResponse<>(Response.Status.FORBIDDEN, "", null);
        }

        LOG.info("the login response:");
        LOG.info(response.toString());

        LOG.info("In postLogin - end");
        return response.build();
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
    @Path("verifyTotp")
    @ZeppelinApi
    public Response postVerifyTotp(@FormParam("totp") String totp) throws Exception {
        LOG.info("In postVerifyTotp - start");

        JsonResponse<Map<String, String>> response = null;
        if (totp == null) { // TODO: use string static methods to check for empty and null
            // TODO: maybe a custom message or expection or smth - TBD
            response = new JsonResponse<>(Response.Status.FORBIDDEN, "", null);
            return response.build();
        }

        Subject currentUser = SecurityUtils.getSubject();
        CognitoUser user = (CognitoUser) SecurityUtils.getSubject().getPrincipals().getPrimaryPrincipal();
        if (currentUser.isAuthenticated() && user != null) {
            LOG.info("auth - we proceed with login");
            LOG.info("username");
            LOG.info(user.getUsername());
            LOG.info("user pool id");
            LOG.info(this.getUserPoolId());

            String sessionToUse = "AYABeJUeFlRo8-ywKdhXF5XyLasAHQABAAdTZXJ2aWNlABBDb2duaXRvVXNlclBvb2xzAAEAB2F3cy1rbXMATmFybjphd3M6a21zOmV1LWNlbnRyYWwtMTo1OTA0OTA4MDk4NTg6a2V5LzRkMmU1YTdmLTFjZDctNDljOS04ZmFjLTJkOWRjYjVjZWY5ZgC4AQIBAHg-pjuNKvPKxtnKU3PADgyxqGsH7MeCPUPkKqeoBvImXgE_qlkODxRvmvXIcnjejQMUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMWxJSKxUDI8vAflYzAgEQgDuyipquQ9Sm1uersBsT_7zxoxAFLMecPxTmQQs2mihhwE12U7ta-3ca-XhY946NmpVJ55uY8JtqhjHFOwIAAAAADAAAEAAAAAAAAAAAAAAAAADo3jUoriPyDDR-BScOD-uV_____wAAAAEAAAAAAAAAAAAAAAEAAAEi32jhzCAi6XkAE5iVB8W3UxVtW7qEKEZwdoeBnsE7Hv1-fH9y5C9-csBM4hLHb_V2z5N9szHSdtNFtYb6SKCM0xAFL2a8fnV4-g6jj9ZGTxblIQ4gVFeynLILwWEWuBU9PnnWq1S3Kc9MrS3OYEbGiS0HjtrRI-JlM45eDjLi53OA39QtUgCc1SnZWTTBSaIX-XDhJjajqDNTX_1mNqGFO7w67ZEmThOgle2jbaM_pd4SFT_-yB-JGMGczl9HXbTmf5WvRzkvgfshT-45U-rR120nwA4q9O3mLXAA5roxjzf9LMdfeCZxfI2Fo2-tfmrAtPJMt6Z_iUN1epOdz851fJCgPnwu202_utqNVxnYHboAC0DShh9h8S8q5Tgkx_ZJqO3-u9vwqSFU3TWbkWJpCImZ";//user.getAdminInitiateAuthResult().getSession();
//            user.isMfaSetup()
//                    ? user.getAssociateSession()
//                    : user.getAdminInitiateAuthResult().getSession();
            LOG.info("sessionToUse");
            LOG.info(sessionToUse);

//            String sessionToUse = user.getInitiateAuthResult().getSession();
//            LOG.info("sessionToUse");
//            LOG.info(sessionToUse);

            //this.cognitoClient.registerSoftwareMFAPreferences(user.getUsername(), this.getUserPoolId());
            VerifySoftwareTokenResult tokenResult = this.cognitoClient.verifySoftwareTokenForAppMFA(sessionToUse, totp);
            LOG.info("VerifySoftwareTokenResult: " + tokenResult);

            if (tokenResult != null) {
                Set<String> roles = authenticationService.getAssociatedRoles();
                String principal = authenticationService.getPrincipal();
                String ticket = "anonymous".equals(principal) ? "anonymous" : TicketContainer.instance.getTicket(principal);
                Map<String, String> data = new HashMap<>();
                data.put("principal", principal);
                data.put("roles", GSON.toJson(roles));
                data.put("ticket", ticket);
                data.put("cognitoSession", user.getCognitoMfaToken());
                response = new JsonResponse<>(Status.OK, "", data);
                return response.build();
            }
        } else {
            LOG.info("user is NULL");
        }

        // TODO: maybe refactor the "not auth" branch
        if (response == null) {
            response = new JsonResponse<>(Response.Status.FORBIDDEN, "", null);
        }

        LOG.info("the login response:");
        LOG.info(response.toString());

        LOG.info("In postVerifyTotp - end");
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
