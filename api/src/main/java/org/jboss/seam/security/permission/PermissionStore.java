package org.jboss.seam.security.permission;

import java.util.List;
import java.util.Set;

/**
 * Permission store interface.
 * 
 * @author Shane Bryzak
 */
public interface PermissionStore
{
   List<Permission> listPermissions(Object target);
   List<Permission> listPermissions(Object target, String action);
   List<Permission> listPermissions(Set<Object> targets, String action);
   boolean grantPermission(Permission permission);
   boolean grantPermissions(List<Permission> permissions);
   boolean revokePermission(Permission permission);
   boolean revokePermissions(List<Permission> permissions);
   List<String> listAvailableActions(Object target);
   void clearPermissions(Object target);
}
