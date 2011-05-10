package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.jboss.seam.security.Identity;

/**
 * Resolves dynamically-assigned permissions, mapped to a user or a role, and kept in persistent
 * storage, such as a relational database.
 *
 * @author Shane Bryzak
 */
public
@SessionScoped
class PersistentPermissionResolver implements PermissionResolver, Serializable {
    private static final long serialVersionUID = -603389172032219059L;

    @Inject
    Identity identity;
    @Inject
    PermissionStore permissionStore;

    @Inject
    Instance<RuleBasedPermissionResolver> ruleBasedPermissionResolver;

    public PermissionStore getPermissionStore() {
        return permissionStore;
    }

    public void setPermissionStore(PermissionStore permissionStore) {
        this.permissionStore = permissionStore;
    }

    public boolean hasPermission(Object target, String action) {
        if (permissionStore == null) return false;

        if (!identity.isLoggedIn()) return false;

        if (!permissionStore.isEnabled()) return false;

        List<Permission> permissions = permissionStore.listPermissions(target, action);

        String username = identity.getUser().getId();

        if (permissions != null) {
            for (Permission permission : permissions) {
                if (//permission.getIdentity() instanceof SimplePrincipal &&
                        username.equals(permission.getIdentity().getName())) {
                    return true;
                }

                //if (permission.getRecipient() instanceof RoleImpl)
                //{
                // RoleImpl role = (RoleImpl) permission.getRecipient();

                // TODO fix this
                /*if (role.isConditional())
                {
                   if (ruleBasedPermissionResolver.checkConditionalRole(role.getRoleType(), target, action)) return true;
                }
                else if (identity.hasRole(role.getRoleType()))
                {
                   return true;
                }*/
                //}
            }
        }

        return false;
    }

    public void filterSetByAction(Set<Object> targets, String action) {
        if (permissionStore == null) return;

        if (!identity.isLoggedIn()) return;

        List<Permission> permissions = permissionStore.listPermissions(targets, action);

        String username = identity.getUser().getId();

        Iterator<?> iter = targets.iterator();
        while (iter.hasNext()) {
            Object target = iter.next();

            for (Permission permission : permissions) {
                if (permission.getResource().equals(target)) {
                    if (//permission.getIdentity() instanceof SimplePrincipal &&
                            username.equals(permission.getIdentity().getName())) {
                        iter.remove();
                        break;
                    }

                    //if (permission.getRecipient() instanceof RoleImpl)
                    //{
                    // RoleImpl role = (RoleImpl) permission.getRecipient();

                    // TODO fix this
                    /*
                    if (role.isConditional())
                    {
                       if (ruleBasedPermissionResolver.checkConditionalRole(role.getName(), target, action))
                       {
                          iter.remove();
                          break;
                       }
                    }
                    else if (identity.hasRole(role.getRoleType()))
                    {
                       iter.remove();
                       break;
                    }*/
                    //}
                }
            }
        }
    }
}
