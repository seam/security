package org.jboss.seam.security.management;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The identity store does the actual work of persisting user accounts and roles in a
 * database, LDAP directory, etc.  
 * 
 * @author Shane Bryzak
 */
public interface IdentityStore
{     
   public enum Feature { createUser, deleteUser, enableUser, disableUser, changePassword, 
      createRole, deleteRole, grantRole, revokeRole }
   
   /**
    * Represents a set of optional features that an IdentityStore implementation might support.
    */
   public class FeatureSet implements Serializable
   {                             
      private static final long serialVersionUID = 1100272929055626911L;
      
      private Set<Feature> features;

      public FeatureSet()
      {
         this(null);
      }
      
      public FeatureSet(Set<Feature> features)
      {
         if (features != null)
         {
            this.features = features;
         }
         else
         {
            this.features = new HashSet<Feature>();
         }
      }
      
      public Set<Feature> getFeatures()
      {
         return features;
      }
      
      public boolean supports(Feature feature)
      {
         return features.contains(feature);
      }
      
      public void addFeature(Feature feature)
      {
         features.add(feature);
      }
      
      public void removeFeature(Feature feature)
      {
         features.remove(feature);
      }
      
      public void enableAll()
      {
         for (Feature f : Feature.values()) addFeature(f);
      }
   }

   /**
    * Returns true if the IdentityStore implementation supports the specified feature.
    * 
    */
   boolean supportsFeature(Feature feature);

   /**
    * Creates a new user with the specified username and password.
    * @return true if the user was successfully created.
    */
   boolean createUser(String username, String password);
   
   /**
    * Creates a new user with the specified username, password, first name and last name.
    * 
    * @return true if the user was successfully created.
    */
   boolean createUser(String username, String password, String firstname, String lastname);
   
   /**
    * Deletes the user with the specified username.
    * @return true if the user was successfully deleted.
    */
   boolean deleteUser(String name);   
   
   /**
    * Enables the user with the specified username.  Enabled users are able to authenticate.
    * @return true if the specified user was successfully enabled.
    */
   boolean enableUser(String name);
   
   /**
    * Disables the user with the specified username.  Disabled users are unable to authenticate.
    * @return true if the specified user was successfully disabled.
    */
   boolean disableUser(String name);   
   
   /**
    * Returns true if the specified user is enabled.
    */
   boolean isUserEnabled(String name);
   
   /**
    * Changes the password of the specified user to the specified password.
    * @return true if the user's password was successfully changed.
    */
   boolean changePassword(String name, String password);   
   
   /**
    * Returns true if the specified user exists.
    */
   boolean userExists(String name);

   /**
    * Creates a new role with the specified role name.
    * @return true if the role was created successfully.
    */
   boolean createRole(String role);
   
   /**
    * Grants the specified role to the specified user.
    * 
    * @param name The name of the user
    * @param role The name of the role to grant to the user.
    * @return true if the role was successfully granted.
    */
   boolean grantRole(String name, String role);
   
   /**
    * Revokes the specified role from the specified user.
    * 
    * @param name The name of the user
    * @param role The name of the role to grant to the user.
    * @return true if the role was successfully revoked.
    */
   boolean revokeRole(String name, String role);
   
   /**
    * Deletes the specified role.
    * @return true if the role was successfully deleted.
    */
   boolean deleteRole(String role);
   
   /**
    * Returns true if the specified role exists.
    */
   boolean roleExists(String name);
   
   /**
    * Adds the specified role as a member of the specified group.
    * 
    * @param role The name of the role to add as a member
    * @param group The name of the group that the specified role will be added to.
    * @return true if the role was successfully added to the group.
    */
   boolean addRoleToGroup(String role, String group);
   
   /**
    * Removes the specified role from the specified group.
    * 
    * @param role The name of the role to remove from the group.
    * @param group The group from which to remove the role.
    * @return true if the role was successfully removed from the group.
    */
   boolean removeRoleFromGroup(String role, String group);   

   /**
    * Returns a list of all users.
    */
   List<String> listUsers();
   
   /**
    * Returns a list of all users containing the specified filter text within their username.

    */
   List<String> listUsers(String filter);
   
   /**
    * Returns a list of all the roles.
    */
   List<String> listRoles();
   
   /**
    * Returns a list of roles that can be granted (i.e, excluding conditional roles)
    */
   List<String> listGrantableRoles();

   /**
    * Returns a list of all the roles explicitly granted to the specified user.
    */
   List<String> getGrantedRoles(String name);
   
   /**
    * Returns a list of all roles that the specified user is a member of.  This list may contain
    * roles that may not have been explicitly granted to the user, which are indirectly implied
    * due to group memberships.

    */
   List<String> getImpliedRoles(String name);
   
   /**
    * Returns a list of all the groups that the specified role is a member of.
    */
   List<String> getRoleGroups(String name);
   
   /**
    * Lists the members of the specified role.
    */
   List<Principal> listMembers(String role);

   /**
    * Authenticates the specified user, using the specified password.
    * 
    * @return true if authentication is successful.
    */
   boolean authenticate(String username, String password);
}
