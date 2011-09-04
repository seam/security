package org.jboss.seam.security.permission;

import java.io.Serializable;

import org.picketlink.idm.spi.model.IdentityObject;

/**
 * Represents a single permission for a particular target, action and recipient combination.
 *
 * @author Shane Bryzak
 */
public class Permission implements Serializable {
    private static final long serialVersionUID = 8998625911493711034L;
    
    private Object resource;
    private String permission;
    private IdentityObject identity;

    public Permission(Object resource, String permission, IdentityObject identity) {
        this.resource = resource;
        this.permission = permission;
        this.identity = identity;
    }

    public Object getResource() {
        return resource;
    }

    public String getPermission() {
        return permission;
    }

    public IdentityObject getIdentity() {
        return identity;
    }
}
