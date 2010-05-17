package org.jboss.seam.security.management.picketlink;

import java.util.List;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;

import org.jboss.seam.security.management.IdentityStore;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.PersistenceManager;
import org.picketlink.idm.api.Role;

@Dependent
public class PicketLinkIdentityStore implements IdentityStore
{
   @Inject IdentitySession identitySession;

   public boolean createGroup(String name)
   {
      // TODO Auto-generated method stub
      PersistenceManager pm = identitySession.getPersistenceManager();
      
      return false;
   }



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
