package org.jboss.seam.security.management;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.jboss.seam.security.GroupImpl;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.UserImpl;
import org.jboss.seam.security.util.Strings;
import org.jboss.seam.transaction.Transactional;
import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;
import org.picketlink.idm.api.query.QueryException;
import org.picketlink.idm.api.query.UserQuery;
import org.picketlink.idm.api.query.UserQueryBuilder;
import org.picketlink.idm.common.exception.FeatureNotSupportedException;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.api.IdentitySearchCriteriaImpl;
import org.picketlink.idm.impl.api.model.SimpleUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default IdentityManager implementation, backed by PicketLink IDM 
 * 
 * @author Shane Bryzak
 */
@RequestScoped
public class IdentityManagerImpl implements IdentityManager, Serializable
{
   private static final long serialVersionUID = 6864253169970552893L;
   
   public static final String RESOURCE_IDENTITY = "seam.identity";
   public static final String RESOURCE_RELATIONSHIP = "seam.relationship";
   
   public static final String PERMISSION_CREATE = "create";
   public static final String PERMISSION_READ = "read";
   public static final String PERMISSION_UPDATE = "update";
   public static final String PERMISSION_DELETE = "delete";
   
   private Logger log = LoggerFactory.getLogger(IdentityManager.class);
   
   @Inject BeanManager manager;
   @Inject Identity identity;
   
   @Inject IdentitySession identitySession;
   
   public @Transactional boolean createUser(String name, Credential credential)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_CREATE);
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
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_DELETE);
      
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
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      //return identityStore.enableUser(name);
      return false;
   }
   
   public boolean disableUser(String name)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      //return identityStore.disableUser(name);
      return false;
   }
   
   public boolean updateCredential(String name, Credential credential)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      
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
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_READ);
      //return identityStore.isUserEnabled(name);
      return false;
   }
   
   public void setUserAttribute(String username, String attribute, Object value)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      try
      {
         identitySession.getAttributesManager().addAttribute(username, attribute, value);
      }
      catch (IdentityException e)
      {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }
   }
   
   public void deleteUserAttribute(String username, String attribute)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);      
      try
      {
         identitySession.getAttributesManager().removeAttributes(username, new String[] {attribute});
      }
      catch (IdentityException e)
      {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }
   }
   
   public boolean grantRole(String name, String role, String groupName, String groupType)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      //return roleIdentityStore.grantRole(name, role, groupName, groupType);
      return false;
   }
   
   public boolean revokeRole(String name, String role, String groupName, String groupType)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      //return roleIdentityStore.revokeRole(name, role, groupName, groupType);
      return false;
   }   

   public boolean associateUser(String groupName, String groupType, String username)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
      //return identityStore.associateUser(groupName, groupType, username);
      return false;
   }
   
   public boolean disassociateUser(String groupName, String groupType, String username)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_UPDATE);
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
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_CREATE);
      //return roleIdentityStore.createRoleType(roleType);
      return false;
   }
   
   public boolean deleteRoleType(String roleType)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_DELETE);
      //return roleIdentityStore.deleteRoleType(roleType);
      return false;
   }
   
   public boolean createGroup(String groupName, String groupType)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_CREATE);
      //return groupIdentityStore.createGroup(groupName, groupType);
      return false;
   }
   
   public boolean deleteGroup(String groupName, String groupType)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_DELETE);
      //return groupIdentityStore.deleteGroup(groupName, groupType);
      return false;
   }
      
   public boolean userExists(String name)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_READ);
      //return identityStore.userExists(name);
      return false;
   }
   
   public boolean roleTypeExists(String roleType)
   {
      //return roleIdentityStore.roleTypeExists(roleType);
      return false;
   }
      
   public Collection<User> findUsers(String filter)
   {
      identity.checkPermission(RESOURCE_IDENTITY, PERMISSION_READ);
      UserQueryBuilder builder = identitySession.createUserQueryBuilder();
      UserQuery userQuery = builder.createQuery();
      
      try
      {
         return identitySession.execute(userQuery);         
      }
      catch (QueryException ex)
      {
         throw new RuntimeException("Error querying users", ex);
      }
   }
   
   public List<String> listRoleTypes()
   {
     // identity.checkPermission(ROLE_PERMISSION_NAME, PERMISSION_READ);
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
   public Collection<Role> getGrantedRoles(String username)
   {
      identity.checkPermission(RESOURCE_RELATIONSHIP, PERMISSION_READ);
      try
      {
         Collection<Role> roles = new ArrayList<Role>();
         
         Collection<RoleType> roleTypes = identitySession.getRoleManager().findUserRoleTypes(new UserImpl(username));
                           
         for (RoleType roleType : roleTypes)
         {
            roles.addAll(identitySession.getRoleManager().findRoles(username, roleType.getName()));
         }
         
         return roles;
      }
      catch (IdentityException e)
      {
         throw new RuntimeException(e);
      }
      catch (FeatureNotSupportedException e)
      {
         throw new RuntimeException(e);
      }
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
   
   public Collection<User> listRoleMembers(String roleType, String groupName, String groupType)
   {
      identity.checkPermission(RESOURCE_RELATIONSHIP, PERMISSION_READ);
      Group group = new GroupImpl(groupType, groupName);      
      IdentitySearchCriteriaImpl criteria = new IdentitySearchCriteriaImpl();
      
      try
      {
         return identitySession.getRoleManager().findUsersWithRelatedRole(group, criteria);
      }
      catch (IdentityException e)
      {
         throw new RuntimeException(e);
      }
      catch (FeatureNotSupportedException e)
      {
         throw new RuntimeException(e);         
      }
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
         log.error("Exception during authentication", ex);
         return false;
      }
   }
   

}
