package org.jboss.seam.security.management;

import java.security.Principal;
import java.util.List;

/**
 * Identity Management API, deals with user name/password-based identity management.
 * 
 * @author Shane Bryzak
 */
public interface IdentityManager
{  
   boolean createUser(String name, String password);

   boolean createUser(String name, String password, String firstname, String lastname);
   
   boolean deleteUser(String name);
   
   boolean enableUser(String name);
   
   boolean disableUser(String name);
   
   boolean changePassword(String name, String password);
   
   boolean isUserEnabled(String name);
   
   boolean grantRole(String name, String role);
   
   boolean revokeRole(String name, String role);
   
   boolean createRole(String role);
   
   boolean deleteRole(String role);
   
   boolean addRoleToGroup(String role, String group);
   
   boolean removeRoleFromGroup(String role, String group);
   
   boolean userExists(String name);
   
   boolean roleExists(String name);
   
   List<String> getUsers();
   
   List<String> getUsers(String filter);
   
   List<String> getRoles();
   
   List<String> getGrantableRoles();
   
   /**
    * Returns a list of the roles that are explicitly granted to the specified user;
    * 
    * @param name The user for which to return a list of roles
    * @return List containing the names of the granted roles
    */
   List<String> getGrantedRoles(String name);
   
   /**
    * Returns a list of roles that are either explicitly or indirectly granted to the specified user.
    * 
    * @param name The user for which to return the list of roles
    * @return List containing the names of the implied roles
    */
   List<String> getImpliedRoles(String name);
   
   List<Principal> listMembers(String role);
   
   List<String> getRoleGroups(String name);
   
   boolean authenticate(String username, String password);
   
   IdentityStore getIdentityStore();
   
   void setIdentityStore(IdentityStore identityStore);
   
   IdentityStore getRoleIdentityStore();
   
   void setRoleIdentityStore(IdentityStore roleIdentityStore);
   
   boolean isEnabled();
}
