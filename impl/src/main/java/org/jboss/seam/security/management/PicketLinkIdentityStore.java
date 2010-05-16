package org.jboss.seam.security.management;

import java.security.Principal;
import java.util.List;

public class PicketLinkIdentityStore implements IdentityStore
{

   public boolean addRoleToGroup(String role, String group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean authenticate(String username, String password)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean changePassword(String name, String password)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createRole(String role)
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

   public boolean deleteRole(String role)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteUser(String name)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean disableUser(String name)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean enableUser(String name)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public List<String> getGrantedRoles(String name)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> getImpliedRoles(String name)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> getRoleGroups(String name)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean grantRole(String name, String role)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean isUserEnabled(String name)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public List<String> listGrantableRoles()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<Principal> listMembers(String role)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> listRoles()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> listUsers()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> listUsers(String filter)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean removeRoleFromGroup(String role, String group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean revokeRole(String name, String role)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean roleExists(String name)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean supportsFeature(Feature feature)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean userExists(String name)
   {
      // TODO Auto-generated method stub
      return false;
   }

}
