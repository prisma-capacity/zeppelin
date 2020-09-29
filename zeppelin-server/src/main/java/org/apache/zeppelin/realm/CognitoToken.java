package org.apache.zeppelin.realm;

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.zeppelin.common.JsonSerializable;

import java.text.ParseException;

public class CognitoToken extends UsernamePasswordToken implements JsonSerializable {
    public String access_token;
    public String id_token;
    public String refresh_token;
    private static final Gson gson = new Gson();

    public CognitoToken(JWTClaimsSet claims) throws ParseException {
        String userName = claims.getStringClaim("cognito:username");
        setUsername(userName);
    }

    public CognitoToken(String username, String password) {
        super(username, password);
    }

    @Override
    public String toJson() {
        return gson.toJson(this);
    }

    public static CognitoToken fromJson(String json) {
        return gson.fromJson(json, CognitoToken.class);
    }
}
