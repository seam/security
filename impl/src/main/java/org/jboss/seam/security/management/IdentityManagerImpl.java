package org.jboss.seam.security.management;

import java.io.Serializable;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.util.Strings;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default IdentityManager implementation 
 * 
 * @author Shane Bryzak
 */
@Named @ApplicationScoped
public class IdentityManagerImpl implements IdentityManager, Serializable
{
   private static final long serialVersionUID = 6864253169970552893L;
   
   public static final String USER_PERMISSION_NAME = "seam.user";
   public static final String ROLE_PERMISSION_NAME = "seam.role";
   public static final String GROUP_PERMISSION_NAME = "seam.group";
   
   public static final String PERMISSION_CREATE = "create";
   public static final String PERMISSION_READ = "read";
   public static final String PERMISSION_UPDATE = "update";
   public static final String PERMISSION_DELETE = "delete";
   
   private Logger log = LoggerFactory.getLogger(IdentityManager.class);
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   
   protected IdentityStore identityStore;
   protected IdentityStore roleIdentityStore;
   protected IdentityStore groupIdentityStore;
   
   @PostConstruct
   public void create()
   {
      if (roleIdentityStore == null && identityStore != null)
      {
         roleIdentityStore = identityStore;
      }
      
      if (identityStore == null)
      {
         log.warn("No identity store available - please configure an identityStore if identity " +
               "management is required.");
      }
      
      if (roleIdentityStore == null)
      {
         log.warn("No role identity store available - please configure a roleIdentityStore if identity " +
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
   
   public boolean grantRole(String name, String role, Group group)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return roleIdentityStore.grantRole(name, role, group);
   }
   
   public boolean revokeRole(String name, String role, Group group)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      return roleIdentityStore.revokeRole(name, role, group);
   }
   
   public boolean createRoleType(String roleType)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_CREATE);
      return roleIdentityStore.createRoleType(roleType);
   }
   
   public boolean deleteRoleType(String roleType)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_DELETE);
      return roleIdentityStore.deleteRoleType(roleType);
   }
   
   public boolean createGroup(String name, String groupType)
   {
      identity.checkPermission(GROUP_PERMISSION_NAME, PERMISSION_CREATE);
      return groupIdentityStore.createGroup(name, groupType);
   }
   
   public boolean deleteGroup(String name, String groupType)
   {
      identity.checkPermission(GROUP_PERMISSION_NAME, PERMISSION_DELETE);
      return groupIdentityStore.deleteGroup(name, groupType);
   }
   
   public boolean userExists(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      return identityStore.userExists(name);
   }
   
   public boolean roleExists(String roleType)
   {
      return roleIdentityStore.roleTypeExists(roleType);
   }
   
   public List<String> getUsers()
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      List<String> users = identityStore.findUsers();
      
      Collections.sort(users, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return users;
   }
   
   public List<String> getUsers(String filter)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      List<String> users = identityStore.findUsers(filter);
      
      Collections.sort(users, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return users;
   }
   
   public List<String> getRoles()
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
      List<String> roles = roleIdentityStore.listRoleTypes();
      
      Collections.sort(roles, new Comparator<String>() {
         public int compare(String value1, String value2) {
            return value1.compareTo(value2);
         }
      });
      
      return roles;
   }
   
   public List<String> getGrantableRoles()
   {
      List<String> roles = roleIdentityStore.listGrantableRoleTypes();
      
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
   public List<Role> getGrantedRoles(String username)
   {
      return roleIdentityStore.listGrantedRoles(username);
   }
   
   /**
    * Returns a list of roles that are either explicitly or indirectly granted to the specified user.
    * 
    * @param name The user for which to return the list of roles
    * @return List containing the names of the implied roles
    */
   public List<Role> getImpliedRoles(String username)
   {
      return roleIdentityStore.listImpliedRoles(username);
   }
   
   public List<IdentityType> listRoleMembers(String roleType, Group group)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
      return roleIdentityStore.listRoleMembers(roleType, group);
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
