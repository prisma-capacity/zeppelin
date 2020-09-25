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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;

public class CognitoJwtVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(CognitoRealm.class);

    private String cognitoUserPoolUrl;
    private String cognitoUserPoolClientId;

    public CognitoJwtVerifier() throws MalformedURLException {
        LOG.info("Init CognitoJwtVerifier");
        //cognitoUserPoolUrl + "/.well-known/jwks.json"));
    }

    public JWTClaimsSet verifyJwt(String token) throws ParseException, JOSEException, BadJOSEException, MalformedURLException {
        JWKSource jwkSource = new RemoteJWKSet<>(new URL(cognitoUserPoolUrl + "/.well-known/jwks.json"));

        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor<>();
        JWSAlgorithmFamilyJWSKeySelector keySelector = new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.RSA, jwkSource);

        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder()
                        .issuer(cognitoUserPoolUrl)
                        .audience(cognitoUserPoolClientId)
                        .claim("token_use", "id")
                        .build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp", "email"))));

        return jwtProcessor.process(token, null);
    }

    public void setCognitoUserPoolUrl(String cognitoUserPoolUrl) {
        LOG.info("setCognitoUserPoolUrl: " + cognitoUserPoolUrl);
        this.cognitoUserPoolUrl = cognitoUserPoolUrl;
    }

    public void setCognitoUserPoolClientId(String cognitoUserPoolClientId) {
        LOG.info("cognitoUserPoolClientId: " + cognitoUserPoolClientId);
        this.cognitoUserPoolClientId = cognitoUserPoolClientId;
    }
}
