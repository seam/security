package org.jboss.seam.security.management;

import java.io.Serializable;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;

import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IdentityStore implementation that allows identity related data to be 
 * persisted in a database via JPA
 *  
 * @author Shane Bryzak
 */
public @ApplicationScoped class JpaIdentityStore implements IdentityStore, Serializable
{
   private static final long serialVersionUID = 7729139146633529501L;
   
   private Logger log = LoggerFactory.getLogger(JpaIdentityStore.class);
   
   private Class<?> identityObjectEntity;
   private Class<?> identityObjectRelationshipEntity;
   private Class<?> identityObjectCredentialEntity;
   private Class<?> identityObjectAttributeEntity;
   
   @Inject PasswordEncoder passwordEncoder;

   public boolean addUserToGroup(String username, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean authenticate(String username, String password)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean changePassword(String username, String password)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createGroup(String name, String groupType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createRoleType(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createUser(String username, String password)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createUser(String username, String password,
         String firstname, String lastname)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteGroup(String name, String groupType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteRoleType(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteUser(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean disableUser(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean enableUser(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public Group findGroup(String name, String groupType)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> findUsers()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> findUsers(String filter)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean grantRole(String username, String roleType, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean isUserEnabled(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public List<String> listGrantableRoleTypes()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<Role> listGrantedRoles(String username)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<IdentityType> listGroupMembers(Group group)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<Role> listImpliedRoles(String username)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<IdentityType> listRoleMembers(String roleType, Group group)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> listRoleTypes()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean removeUserFromGroup(String username, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean revokeRole(String username, String roleType, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean roleTypeExists(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean supportsFeature(Feature feature)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean userExists(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

}
