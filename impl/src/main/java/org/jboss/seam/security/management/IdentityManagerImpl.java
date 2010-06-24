package org.jboss.seam.security.management;

import java.io.Serializable;
import java.util.List;

import javax.enterprise.inject.Model;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.util.Strings;
import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.User;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.api.model.SimpleUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default IdentityManager implementation 
 * 
 * @author Shane Bryzak
 */
@Model
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
   
   @Inject IdentitySession identitySession;
   
   public boolean createUser(String name, Credential credential)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_CREATE);
      try
      {
         User user = identitySession.getPersistenceManager().createUser(name);
         identitySession.getAttributesManager().updateCredential(user, credential);         
         return true;
      }
      catch (IdentityException ex)
      {
         throw new RuntimeException("Error creating user", ex);
      }
   }
   
   public boolean deleteUser(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_DELETE);
      
      try
      {
         identitySession.getPersistenceManager().removeUser(name, true);
         return true;
      }
      catch (IdentityException ex)
      {
         throw new RuntimeException("Failed to delete user", ex);
      }
   }
   
   public boolean enableUser(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return identityStore.enableUser(name);
      return false;
   }
   
   public boolean disableUser(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return identityStore.disableUser(name);
      return false;
   }
   
   public boolean updateCredential(String name, Credential credential)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      
      try
      {
         identitySession.getAttributesManager().updateCredential(new SimpleUser(name), credential);
         return true;
      }
      catch (IdentityException ex)
      {
         throw new RuntimeException("Exception updating credential", ex);
      }
   }
   
   public boolean isUserEnabled(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      //return identityStore.isUserEnabled(name);
      return false;
   }
   
   public boolean setUserAttribute(String username, String attribute, Object value)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return identityStore.setUserAttribute(username, attribute, value);
      return false;
   }
   
   public boolean deleteUserAttribute(String username, String attribute)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return identityStore.deleteUserAttribute(username, attribute);
      return false;
   }
   
   public boolean grantRole(String name, String role, String groupName, String groupType)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return roleIdentityStore.grantRole(name, role, groupName, groupType);
      return false;
   }
   
   public boolean revokeRole(String name, String role, String groupName, String groupType)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return roleIdentityStore.revokeRole(name, role, groupName, groupType);
      return false;
   }   

   public boolean associateUser(String groupName, String groupType, String username)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return identityStore.associateUser(groupName, groupType, username);
      return false;
   }
   
   public boolean disassociateUser(String groupName, String groupType, String username)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_UPDATE);
      //return identityStore.disassociateUser(groupName, groupType, username);
      return false;
   }
   
   public boolean associateGroup(String groupName, String groupType, String memberGroupName, String memberGroupType)
   {
      return false;
   }
   
   public boolean disassociateGroup(String groupName, String groupType, String memberGroupName, String memberGroupType)
   {
      return false;
   }
   
   public boolean createRoleType(String roleType)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_CREATE);
      //return roleIdentityStore.createRoleType(roleType);
      return false;
   }
   
   public boolean deleteRoleType(String roleType)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_DELETE);
      //return roleIdentityStore.deleteRoleType(roleType);
      return false;
   }
   
   public boolean createGroup(String groupName, String groupType)
   {
      identity.checkPermission(GROUP_PERMISSION_NAME, PERMISSION_CREATE);
      //return groupIdentityStore.createGroup(groupName, groupType);
      return false;
   }
   
   public boolean deleteGroup(String groupName, String groupType)
   {
      identity.checkPermission(GROUP_PERMISSION_NAME, PERMISSION_DELETE);
      //return groupIdentityStore.deleteGroup(groupName, groupType);
      return false;
   }
      
   public boolean userExists(String name)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      //return identityStore.userExists(name);
      return false;
   }
   
   public boolean roleTypeExists(String roleType)
   {
      //return roleIdentityStore.roleTypeExists(roleType);
      return false;
   }
      
   public List<String> findUsers(String filter)
   {
      identity.checkPermission(USER_PERMISSION_NAME, PERMISSION_READ);
      //List<String> users = identityStore.findUsers(filter);
      
      return null;
   }
   
   public List<String> listRoleTypes()
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
      //List<String> roles = roleIdentityStore.listRoleTypes();
      
      return null;
   }
   
   public List<String> getGrantableRoles()
   {
      //List<String> roles = roleIdentityStore.listGrantableRoleTypes();
      
      return null;
   }
   
   /**
    * Returns a list of the roles that are explicitly granted to the specified user;
    * 
    * @param name The user for which to return a list of roles
    * @return List containing the names of the granted roles
    */
   public List<Role> getGrantedRoles(String username)
   {
      //return roleIdentityStore.listGrantedRoles(username);
      return null;
   }
   
   /**
    * Returns a list of roles that are either explicitly or indirectly granted to the specified user.
    * 
    * @param name The user for which to return the list of roles
    * @return List containing the names of the implied roles
    */
   public List<Role> getImpliedRoles(String username)
   {
      //return roleIdentityStore.listImpliedRoles(username);
      return null;
   }
   
   public List<IdentityType> listRoleMembers(String roleType, String groupName, String groupType)
   {
      identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
      //return roleIdentityStore.listRoleMembers(roleType, groupName, groupType);
      return null;
   }
     
   public boolean authenticate(String username, Credential credential)
   {
      if (Strings.isEmpty(username)) return false;
      
      try
      {
         return identitySession.getAttributesManager().validateCredentials(
            new SimpleUser(username), new Credential[] {credential});
      }
      catch (IdentityException ex)
      {
         return false;
      }
   }
   

}
