package org.jboss.seam.security.management;

import java.io.Serializable;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.Role;

/**
 * The identity store does the actual work of persisting user accounts and roles in a
 * database, LDAP directory, etc.  
 * 
 * @author Shane Bryzak
 */
public interface IdentityStore
{     
   public enum Feature { createUser, deleteUser, enableUser, disableUser, 
      changePassword, createRole, deleteRole, grantRole, revokeRole, 
      createGroup, addToGroup, removeFromGroup, deleteGroup }
   
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
    * Creates a new user with the specified username and credential.
    * @return true if the user was successfully created.
    */
   boolean createUser(String username, Credential credential, Map<String,?> attributes);
     
   /**
    * Deletes the user with the specified username.
    * @return true if the user was successfully deleted.
    */
   boolean deleteUser(String username);   
   
   /**
    * Enables the user with the specified username.  Enabled users are able to authenticate.
    * @return true if the specified user was successfully enabled.
    */
   boolean enableUser(String username);
   
   /**
    * Disables the user with the specified username.  Disabled users are unable to authenticate.
    * @return true if the specified user was successfully disabled.
    */
   boolean disableUser(String username);   
   
   /**
    * Returns true if the specified user is enabled.
    */
   boolean isUserEnabled(String username);
   
   /**
    * Updates the credential of the specified user.
    * @return true if the user's credential was successfully changed.
    */
   boolean updateCredential(String username, Credential credential);   
   
   /**
    * Returns true if the specified user exists.
    */
   boolean userExists(String username);

   /**
    * 
    * @param username 
    * @param attribute
    * @param value
    * @return
    */
   boolean setUserAttribute(String username, String attribute, Object value);
   
   /**
    * 
    * @param username
    * @param attribute
    * @return
    */
   boolean deleteUserAttribute(String username, String attribute);
   
   /**
    * Creates a new role type with the specified role type name.
    * @return true if the role type was created successfully.
    */
   boolean createRoleType(String roleType);
   
   /**
    * Grants the specified role to the specified user.
    * 
    * @param name The name of the user
    * @param roleType The name of the role type to grant to the user.
    * @param groupName The name of the group to grant the role in
    * @param groupType The group type
    * @return true if the role was successfully granted.
    */
   boolean grantRole(String username, String roleType, String groupName, String groupType);
   
   /**
    * Revokes the specified role from the specified user.
    * 
    * @param name The name of the user
    * @param roleType The name of the role type to revoke from the user.
    * @param groupName The name of the group which contains the user role
    * @param groupType The group type
    * @return true if the role was successfully revoked.
    */
   boolean revokeRole(String username, String roleType, String groupName, String groupType);   
   
   /**
    * Deletes the specified role type.
    * @return true if the role type was successfully deleted.
    */
   boolean deleteRoleType(String roleType);
   
   /**
    * Returns true if the specified role type exists.
    */
   boolean roleTypeExists(String roleType);
   
   /**
    * Creates a new group with the specified name
    * 
    * @param name The name of the group
    * @return true if the group was created successfully
    */
   boolean createGroup(String name, String groupType);
   
   boolean associateUser(String groupName, String groupType, String username);
   
   boolean disassociateUser(String groupName, String groupType, String username);
   
   boolean associateGroup(String groupName, String groupType, String memberGroupName, String memberGroupType);
   
   boolean disassociateGroup(String groupName, String groupType, String memberGroupName, String memberGroupType);   
   
   /**
    * Deletes the specified group
    * 
    * @param group The name of the group to delete
    * @return true if the group was successfully deleted
    */
   boolean deleteGroup(String name, String groupType);
   
   /**
    * 
    * @param name
    * @param type
    * @return
    */
   Group findGroup(String name, String groupType);
   
   /**
    * Returns a list of all user names containing the specified filter text within their username.
    */
   List<String> findUsers(String filter);
   
   /**
    * Returns a list of all the role types.
    */
   List<String> listRoleTypes();
   
   /**
    * Returns a list of role types that can be granted (i.e, excluding conditional roles)
    */
   List<String> listGrantableRoleTypes();

   /**
    * Returns a list of all the roles explicitly granted to the specified user.
    */
   List<Role> listGrantedRoles(String username);
   
   /**
    * Returns a list of all roles that the specified user is a member of.  This list may contain
    * roles that may not have been explicitly granted to the user, which are indirectly implied
    * due to role memberships.

    */
   List<Role> listImpliedRoles(String username);
     
   /**
    * Lists the members of the specified role
    */
   List<IdentityType> listRoleMembers(String roleType, String groupName, String groupType);
   
   /**
    * Lists the members of the specified group
    */
   List<IdentityType> listGroupMembers(Group group);

   /**
    * Authenticates the specified user, using the specified credential.
    * 
    * @return true if authentication is successful.
    */
   boolean authenticate(String username, Credential credential);
}
