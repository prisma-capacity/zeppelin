package org.apache.zeppelin.realm.cognito;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.GroupType;
import org.apache.zeppelin.realm.PropertiesHelper;
import org.junit.Before;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CognitoClientProviderTest {

    CognitoClientProvider cognitoClientProvider;
    AWSCognitoIdentityProvider cognito;
    private static final Logger LOG = LoggerFactory.getLogger(CognitoClientProviderTest.class);

    @Before
    public void setup() throws IOException {
        Properties props = PropertiesHelper.getProperties(CognitoRealm.class);
        String userPoolId = props.getProperty("userPoolId");
        String userPoolClientId = props.getProperty("userPoolClientId");
        cognito = mock(AWSCognitoIdentityProvider.class);

//        AWSCognitoIdentityProviderClientBuilder awsIdpClientBuilder = mock(AWSCognitoIdentityProviderClientBuilder.class);
//        PowerMockito.mockStatic(AWSCognitoIdentityProviderClientBuilder.class);
//        PowerMockito.when(AWSCognitoIdentityProviderClientBuilder.standard()).thenReturn(awsIdpClientBuilder);
//        PowerMockito.when(AWSCognitoIdentityProviderClientBuilder.standard().withRegion(anyString())).thenReturn(awsIdpClientBuilder);
//        PowerMockito.when(AWSCognitoIdentityProviderClientBuilder.standard().withRegion(anyString()).build()).thenReturn(cognito);
        cognitoClientProvider = new CognitoClientProvider(userPoolClientId, userPoolId);

        List<GroupType> mockedGroups = new ArrayList<>();
        GroupType admin = new GroupType();
        admin.setGroupName("test");
        mockedGroups.add(admin);
        //when(cognito.listGroups(any()).getGroups()).thenReturn(mockedGroups);
    }

    @Test
    public void testGetCognitoGroups() {
        List<String> groups = cognitoClientProvider.getCognitoGroups();
        List<String> resultGroups = new ArrayList<>();
        resultGroups.add("test");
        assertEquals(groups, resultGroups);
    }
}