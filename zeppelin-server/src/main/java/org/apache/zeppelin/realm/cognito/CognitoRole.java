package org.apache.zeppelin.realm.cognito;

import java.util.List;

public class CognitoRole {
    private List<String> permissions;

    public List<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }
}

