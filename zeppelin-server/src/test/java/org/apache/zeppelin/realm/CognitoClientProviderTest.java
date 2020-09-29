package org.apache.zeppelin.realm;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CognitoClientProviderTest {

//    @Test
//    public void getCognito() {
//        AWSCognitoIdentityProviderClientBuilder clientBuilder = Mockito.mock(AWSCognitoIdentityProviderClientBuilder.class);
//        AWSCognitoIdentityProvider cognitoIdentityProvider = Mockito.mock(AWSCognitoIdentityProvider.class);
//        when(clientBuilder.build()).thenReturn(cognitoIdentityProvider);
//
//        CognitoClientProvider uut = new CognitoClientProvider();
//
//        assertEquals(cognitoIdentityProvider, uut.getCognito());
//    }
}