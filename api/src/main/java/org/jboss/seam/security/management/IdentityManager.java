package org.jboss.seam.security.management;

import java.util.List;

import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.Role;

/**
 * Identity Management API, allows management of users, groups and roles.
 * 
 * @author Shane Bryzak
 */
public interface IdentityManager
{  
   /**
    * Creates a new user with the specified username and credential.
    * 
    * @param username The new user's username
    * @param credential The new user's credential
    * @return true if the user was successfully created, false otherwise.
    */
   boolean createUser(String username, Credential credential);
   
   /**
    * Deletes the user with the specified username. This operation also deletes
    * all of the user's credentials, relationships and attributes.
    * 
    * @param username The username of the user to delete
    * @return true if the user was successfully deleted.
    */
   boolean deleteUser(String username);
   
   /**
    * Updates the credentials of the user with the specified username
    * 
    * @param username The username of the user's credential to update
    * @param credential The new credential
    * @return true if the credential was successfully updated
    */
   boolean updateCredential(String username, Credential credential);
      
   /**
    * Checks if the user with the specified username exists
    *  
    * @param username The username of the user
    * @return true if the user exists
    */
   boolean userExists(String username);     
   
   /**
    * Checks if a user account is currently enabled
    * 
    * @param username The username of the user account to check
    * @return true if the user account is enabled
    */
   boolean isUserEnabled(String username);
   
   /**
    * Enables the user account of the specified username
    * 
    * @param username The username of the account to enable
    * @return true if the account was successfully enabled
    */
   boolean enableUser(String username);
   
   /**
    * Disables the user account of the specified username
    *  
    * @param username The username of the account to disable
    * @return true if the account was successfully disabled
    */
   boolean disableUser(String username);
   
   /**
    * Sets the specified attribute value for the specified user
    * 
    * @param username The username of the user 
    * @param attribute The name of the attribute to set
    * @param value The value of the attribute
    * @return true if the attribute was successfully set
    */
   boolean setUserAttribute(String username, String attribute, Object value);
   
   /**
    * Deletes the specified attribute value from the specified user
    * 
    * @param username The username of the user
    * @param attribute The name of the attribute to delete
    * @return true if the attribute was successfully deleted
    */
   boolean deleteUserAttribute(String username, String attribute);

   /**
    * Creates a new role type
    * 
    * @param roleType The name of the new role type
    * @return true if the role type was successfully created
    */
   boolean createRoleType(String roleType);
   
   /**
    * Deletes the specified role type.  All granted roles of the specified
    * role type are deleted also. 
    * 
    * @param roleType The name of the role type to delete
    * @return true if the role type was successfully deleted
    */
   boolean deleteRoleType(String roleType);
   
   /**
    * Creates a new group, with the specified name and of the specified group type
    * 
    * @param name The name of the new group
    * @param groupType The type of the new group
    * @return true if the group was successfully created
    */
   boolean createGroup(String name, String groupType);
   
   /**
    * Deletes the group with the specified name and group type
    *  
    * @param name The name of the group to delete
    * @param groupType The type of the group to delete
    * @return true if the group was successfully deleted
    */
   boolean deleteGroup(String name, String groupType);
   
   /**
    * Grants a role membership to the specified user.
    * 
    * @param username The username of the user being granted role membership
    * @param roleType The role type of the role being granted
    * @param groupName The name of the group the role is being granted in 
    * @param groupType The type of the group
    * @return true if the role was successfully granted
    */
   boolean grantRole(String username, String roleType, String groupName, String groupType);
   
   /**
    * Revokes role membership from the specified user.
    * 
    * @param username The username of the user being revoked role membership
    * @param roleType The role type of the role being revoked
    * @param groupName The name of the group the role is being revoked from
    * @param groupType The type of the group
    * @return true if the role was successfully revoked
    */
   boolean revokeRole(String username, String roleType, String groupName, String groupType);      
   
   /**
    * Adds a user to the specified group 
    *  
    * @param username The username of the user being added to the group
    * @param groupName The name of the group the user is being added to
    * @param groupType The type of the group
    * @return true if the user was successfully added
    */
   boolean addUserToGroup(String username, String groupName, String groupType);
   
   /**
    * Removes a user from the specified group
    * 
    * @param username The username of the user being removed
    * @param groupName The name of the group the user is being removed from
    * @param groupType The type of the group
    * @return true if the user was successfully removed
    */
   boolean removeUserFromGroup(String username, String groupName, String groupType);    
   
   /**
    * Finds users that match the specified filter.  A filter of null will return
    * all users.
    * 
    * @param filter The filter used to perform the search.  
    * @return A list of users that match the specified filter.
    */
   List<String> findUsers(String filter);
   
   /**
    * Returns a list of all the role types.
    * 
    * @return A list of all role types
    */
   List<String> listRoleTypes();
   
   List<String> getGrantableRoles();
   
   /**
    * Returns a list of the roles that are explicitly granted to the specified user;
    * 
    * @param name The user for which to return a list of roles
    * @return List containing the names of the granted roles
    */
   List<Role> getGrantedRoles(String name);
   
   /**
    * Returns a list of roles that are either explicitly or indirectly granted to the specified user.
    * 
    * @param name The user for which to return the list of roles
    * @return List containing the names of the implied roles
    */
   List<Role> getImpliedRoles(String name);
   
   /**
    * Returns a list of all members that have been granted the specified role
    * 
    * @param roleType The role type of the role
    * @param groupName The name of the group the role has been granted in
    * @param groupType The type of the group
    * @return A List of IdentityType objects having membership of the specified role
    */
   List<IdentityType> listRoleMembers(String roleType, String groupName, String groupType);
      
   /**
    * Performs an authentication check using the specified username and credential.
    * This operation does not establish any kind of security context, it simply
    * returns a result indicating whether authentication is successful or not.
    *  
    * @param username The username to authenticate
    * @param credential The credential to authenticate with
    * @return true if authentication was successful, false otherwise.
    */
   boolean authenticate(String username, Credential credential);
   
   IdentityStore getIdentityStore();
   
   void setIdentityStore(IdentityStore identityStore);
   
   IdentityStore getRoleIdentityStore();
   
   void setRoleIdentityStore(IdentityStore roleIdentityStore);
   
   boolean isEnabled();
}
