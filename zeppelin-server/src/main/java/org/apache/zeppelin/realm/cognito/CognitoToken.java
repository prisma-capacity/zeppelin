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
