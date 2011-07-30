package org.jboss.seam.security;

import java.util.Collection;
import java.util.Set;

import org.jboss.seam.security.annotations.LoggedIn;
import org.jboss.seam.security.annotations.Secures;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.User;

/**
 * API for authorization and authentication via Seam security.
 *
 * @author Shane Bryzak
 */
public interface Identity {
    public static final String RESPONSE_LOGIN_SUCCESS = "success";
    public static final String RESPONSE_LOGIN_FAILED = "failed";
    public static final String RESPONSE_LOGIN_EXCEPTION = "exception";

    /**
     * Simple check that returns true if the user is logged in, without attempting to authenticate
     *
     * @return true if the user is logged in
     */
    @Secures
    @LoggedIn
    boolean isLoggedIn();

    /**
     * Returns true if the currently authenticated user has provided their correct credentials
     * within the verification window configured by the application.
     *
     * @return
     */
    boolean isVerified();

    /**
     * Will attempt to authenticate quietly if the user's credentials are set and they haven't
     * authenticated already.  A quiet authentication doesn't throw any exceptions if authentication
     * fails.
     *
     * @return true if the user is logged in, false otherwise
     */
    boolean tryLogin();

    /**
     * Returns the currently authenticated user
     *
     * @return
     */
    User getUser();

    /**
     * Performs an authorization check, based on the specified security expression string.
     *
     * @param expr The security expression string to evaluate
     * @throws NotLoggedInException   Thrown if the authorization check fails and
     *                                the user is not authenticated
     * @throws AuthorizationException Thrown if the authorization check fails and
     *                                the user is authenticated
     */
    void checkRestriction(String expr);

    /**
     * Attempts to authenticate the user.  This method raises the following events in response 
     * to whether authentication is successful or not.  The following events may be raised
     * during the call to login():
     * <p/>
     * org.jboss.seam.security.events.LoggedInEvent - raised when authentication is successful
     * org.jboss.seam.security.events.LoginFailedEvent - raised when authentication fails
     * org.jboss.seam.security.events.AlreadyLoggedInEvent - raised if the user is already authenticated
     *
     * @return String returns RESPONSE_LOGIN_SUCCESS if user is authenticated, 
     * RESPONSE_LOGIN_FAILED if authentication failed, or
     * RESPONSE_LOGIN_EXCEPTION if an exception occurred during authentication. These response
     * codes may be used to control user navigation.  For deferred authentication methods, such as Open ID
     * the login() method will return an immediate result of RESPONSE_LOGIN_FAILED (and subsequently fire
     * a LoginFailedEvent) however in these conditions it is the responsibility of the Authenticator
     * implementation to take over the authentication process, for example by redirecting the user to
     * another authentication service.
     * 
     */
    String login();

    /**
     * Attempts a quiet login, suppressing any login exceptions and not creating
     * any faces messages. This method is intended to be used primarily as an
     * internal API call, however has been made public for convenience.
     */
    void quietLogin();

    /**
     * Logs out the currently authenticated user
     */
    void logout();

    /**
     * Checks if the authenticated user is a member of the specified role.
     *
     * @param role String The name of the role to check
     * @return boolean True if the user is a member of the specified role
     */
    boolean hasRole(String role, String group, String groupType);

    /**
     * Adds a role to the authenticated user.  If the user is not logged in,
     * the role will be added to a list of roles that will be granted to the
     * user upon successful authentication, but only during the authentication
     * process.
     *
     * @param role The name of the role to add
     */
    boolean addRole(String role, String group, String groupType);

    /**
     * Checks if the authenticated user is a member of the specified group
     *
     * @param name      The name of the group
     * @param groupType The type of the group, e.g. "office", "department", "global role", etc
     * @return true if the user is a member of the group
     */
    boolean inGroup(String name, String groupType);

    /**
     * Adds the user to the specified group. See hasRole() for semantics in
     * relationship to the authenticated status of the user.
     *
     * @param name      The name of the group
     * @param groupType The type of the group
     * @return true if the group was successfully added
     */
    boolean addGroup(String name, String groupType);

    /**
     * Removes the currently authenticated user from the specified group
     *
     * @param name      The name of the group
     * @param groupType The type of the group
     */
    void removeGroup(String name, String groupType);

    /**
     * Removes a role from the authenticated user
     *
     * @param role The name of the role to remove
     */
    void removeRole(String role, String group, String groupType);

    /**
     * Checks that the current authenticated user is a member of
     * the specified role.
     *
     * @param role String The name of the role to check
     * @throws AuthorizationException if the authenticated user is not a member of the role
     */
    void checkRole(String role, String group, String groupType);

    /**
     * @param group
     * @param groupType
     */
    void checkGroup(String group, String groupType);

    /**
     * Checks if the currently authenticated user has the specified permission
     * for the specified resource.
     *
     * @param resource   The resource for which the user wishes to perform a restricted action
     * @param permission The name of the permission that the user requires to invoke the operation
     * @throws NotLoggedInException   if the current user is not authenticated
     * @throws AuthorizationException if the current user does not have the necessary
     *                                permission for the specified resource object.
     */
    void checkPermission(Object resource, String permission);

    /**
     * Filters a collection of objects by a specified action, by removing the
     * objects from the collection for which the user doesn't have the necessary
     * privileges to perform the specified action against that object.
     *
     * @param collection The Collection to filter
     * @param action     The name of the action to filter by
     */
    void filterByPermission(Collection<?> collection, String permission);

    /**
     * Checks if the currently authenticated user has the necessary permission for
     * a specific resource.
     *
     * @return true if the user has the required permission, otherwise false
     */
    boolean hasPermission(Object resource, String permission);

    /**
     * Returns an immutable set containing all the current user's granted roles
     *
     * @return
     */
    Set<Role> getRoles();

    /**
     * Returns an immutable set containing all the current user's group memberships
     *
     * @return
     */
    Set<Group> getGroups();

    Class<? extends Authenticator> getAuthenticatorClass();

    void setAuthenticatorClass(Class<? extends Authenticator> authenticatorClass);

    String getAuthenticatorName();

    void setAuthenticatorName(String authenticatorName);
}
