package org.jboss.seam.security.management;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.enterprise.inject.Model;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Identity Management API, deals with user name/password-based identity management.
 * 
 * @author Shane Bryzak
 */
@Model
public class IdentityManager implements Serializable
{
   private static final long serialVersionUID = 6864253169970552893L;
   
   public static final String USER_PERMISSION_NAME = "seam.user";
   public static final String ROLE_PERMISSION_NAME = "seam.role";
   
   public static final String PERMISSION_CREATE = "create";
   public static final String PERMISSION_READ = "read";
   public static final String PERMISSION_UPDATE = "update";
   public static final String PERMISSION_DELETE = "delete";
   
   private Logger log = LoggerFactory.getLogger(IdentityManager.class);
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   
   private IdentityStore identityStore;
   private IdentityStore roleIdentityStore;
   
   @Inject
   public void create()
   {
      if (roleIdentityStore == null && identityStore != null)
      {
         roleIdentityStore = identityStore;
      }
      
      if (identityStore == null || roleIdentityStore == null)
      {
         log.warn("No identity store available - please configure an identityStore if identity " +
               "management is required.");
      }
   }
   
   public boolean createUser(String name, String password)
   {
      return createUser(name, password, null, null);
   }

   public boolean createUser(String name, String password, String firstname, String lastname)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_CREATE);
      return identityStore.createUser(name, password, firstname, lastname);
   }
   
   public boolean deleteUser(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_DELETE);
      return identityStore.deleteUser(name);
   }
   
   public boolean enableUser(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return identityStore.enableUser(name);
   }
   
   public boolean disableUser(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return identityStore.disableUser(name);
   }
   
   public boolean changePassword(String name, String password)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return identityStore.changePassword(name, password);
   }
   
   public boolean isUserEnabled(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      return identityStore.isUserEnabled(name);
   }
   
   public boolean grantRole(String name, String role)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return roleIdentityStore.grantRole(name, role);
   }
   
   public boolean revokeRole(String name, String role)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return roleIdentityStore.revokeRole(name, role);
   }
   
   public boolean createRole(String role)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_CREATE);
      return roleIdentityStore.createRole(role);
   }
   
   public boolean deleteRole(String role)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_DELETE);
      return roleIdentityStore.deleteRole(role);
   }
   
   public boolean addRoleToGroup(String role, String group)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_UPDATE);
      return roleIdentityStore.addRoleToGroup(role, group);
   }
   
   public boolean removeRoleFromGroup(String role, String group)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_UPDATE);
      return roleIdentityStore.removeRoleFromGroup(role, group);
   }
   
   public boolean userExists(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      return identityStore.userExists(name);
   }
   
   public boolean roleExists(String name)
   {
      return roleIdentityStore.roleExists(name);
   }
   
   public List<String> listUsers()
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      List<String> users = identityStore.listUsers();
      
      Collections.sort(users, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return users;
   }
   
   public List<String> listUsers(String filter)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      List<String> users = identityStore.listUsers(filter);
      
      Collections.sort(users, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return users;
   }
   
   public List<String> listRoles()
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
      List<String> roles = roleIdentityStore.listRoles();
      
      Collections.sort(roles, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return roles;
   }
   
   public List<String> listGrantableRoles()
   {
      List<String> roles = roleIdentityStore.listGrantableRoles();
      
      Collections.sort(roles, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return roles;
   }
   
   /**
    * Returns a list of the roles that are explicitly granted to the specified user;
    * 
    * @param name The user for which to return a list of roles
    * @return List containing the names of the granted roles
    */
   public List<String> getGrantedRoles(String name)
   {
      return roleIdentityStore.getGrantedRoles(name);
   }
   
   /**
    * Returns a list of roles that are either explicitly or indirectly granted to the specified user.
    * 
    * @param name The user for which to return the list of roles
    * @return List containing the names of the implied roles
    */
   public List<String> getImpliedRoles(String name)
   {
      return roleIdentityStore.getImpliedRoles(name);
   }
   
   public List<Principal> listMembers(String role)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
      return roleIdentityStore.listMembers(role);
   }
   
   public List<String> getRoleGroups(String name)
   {
      return roleIdentityStore.getRoleGroups(name);
   }
   
   public boolean authenticate(String username, String password)
   {
      if (Strings.isEmpty(username)) return false;
      return identityStore.authenticate(username, password);
   }
   
   public IdentityStore getIdentityStore()
   {
      return identityStore;
   }
   
   public void setIdentityStore(IdentityStore identityStore)
   {
      this.identityStore = identityStore;
   }
   
   public IdentityStore getRoleIdentityStore()
   {
      return roleIdentityStore;
   }
   
   public void setRoleIdentityStore(IdentityStore roleIdentityStore)
   {
      this.roleIdentityStore = roleIdentityStore;
   }
   
   public boolean isEnabled()
   {
      return identityStore != null && roleIdentityStore != null;
   }
   
}
