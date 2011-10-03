package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.Identity;

/**
 * Permission management component, used to grant or revoke permissions on specific objects or of
 * specific permission types to particular users or roles.
 *
 * @author Shane Bryzak
 */
@Named
public class PermissionManager implements Serializable {
    private static final long serialVersionUID = -2694925751585231813L;

    public static final String PERMISSION_READ = "seam.read-permissions";
    public static final String PERMISSION_GRANT = "seam.grant-permission";
    public static final String PERMISSION_REVOKE = "seam.revoke-permission";

    private static final Logger log = Logger.getLogger(PermissionManager.class);

    @Inject
    PermissionStore permissionStore;
    @Inject
    Identity identity;

    public PermissionStore getPermissionStore() {
        return permissionStore;
    }

    public void setPermissionStore(PermissionStore permissionStore) {
        this.permissionStore = permissionStore;
    }

    public List<Permission> listPermissions(Object target, String action) {
        if (target == null) return null;
        identity.checkPermission(target, PERMISSION_READ);
        return permissionStore.listPermissions(target, action);
    }

    public List<Permission> listPermissions(Object target) {
        if (target == null) return null;
        identity.checkPermission(target, PERMISSION_READ);
        return permissionStore.listPermissions(target);
    }

    public boolean grantPermission(Permission permission) {
        identity.checkPermission(permission.getResource(), PERMISSION_GRANT);
        return permissionStore.grantPermission(permission);
    }

    public boolean grantPermissions(List<Permission> permissions) {
        for (Permission permission : permissions) {
            identity.checkPermission(permission.getResource(), PERMISSION_GRANT);
        }
        return permissionStore.grantPermissions(permissions);
    }

    public boolean revokePermission(Permission permission) {
        identity.checkPermission(permission.getResource(), PERMISSION_REVOKE);
        return permissionStore.revokePermission(permission);
    }

    public boolean revokePermissions(List<Permission> permissions) {
        for (Permission permission : permissions) {
            identity.checkPermission(permission.getResource(), PERMISSION_REVOKE);
        }
        return permissionStore.revokePermissions(permissions);
    }

    public List<String> listAvailableActions(Object target) {
        return permissionStore.listAvailableActions(target);
    }

    public void clearPermissions(Object target) {
        if (permissionStore != null) {
            permissionStore.clearPermissions(target);
        }
    }
}
