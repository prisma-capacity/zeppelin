package org.apache.zeppelin.realm;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;

public class CognitoClientProvider {
    private AWSCognitoIdentityProvider cognito;

    public CognitoClientProvider() {
        this.cognito = AWSCognitoIdentityProviderClientBuilder
                .standard()
                .withRegion("eu-central-1")
                .build();
    }

    public AWSCognitoIdentityProvider getCognito() {
        return cognito;
    }
}
