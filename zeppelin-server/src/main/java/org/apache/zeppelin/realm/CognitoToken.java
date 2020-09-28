package org.apache.zeppelin.realm;

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.zeppelin.common.JsonSerializable;

import java.text.ParseException;

public class CognitoToken implements JsonSerializable, AuthenticationToken {
    public String access_token;
    public String id_token;
    public String refresh_token;
    private static final Gson gson = new Gson();

    @Override
    public String toJson() {
        return gson.toJson(this);
    }

    public static CognitoToken fromJson(String json) {
        return gson.fromJson(json, CognitoToken.class);
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return id_token;
    }
}
