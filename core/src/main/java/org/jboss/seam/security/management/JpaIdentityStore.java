package org.jboss.seam.security.management;

import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.Role;
import org.jboss.seam.security.SimplePrincipal;
import org.jboss.seam.security.annotations.management.PasswordSalt;
import org.jboss.seam.security.annotations.management.RoleConditional;
import org.jboss.seam.security.annotations.management.RoleGroups;
import org.jboss.seam.security.annotations.management.RoleName;
import org.jboss.seam.security.annotations.management.UserEnabled;
import org.jboss.seam.security.annotations.management.UserFirstName;
import org.jboss.seam.security.annotations.management.UserLastName;
import org.jboss.seam.security.annotations.management.UserPassword;
import org.jboss.seam.security.annotations.management.UserPrincipal;
import org.jboss.seam.security.annotations.management.UserRoles;
import org.jboss.seam.security.crypto.BinTools;
import org.jboss.seam.security.events.PrePersistUserEvent;
import org.jboss.seam.security.events.PrePersistUserRoleEvent;
import org.jboss.seam.security.events.UserAuthenticatedEvent;
import org.jboss.seam.security.events.UserCreatedEvent;
import org.jboss.seam.security.util.AnnotatedBeanProperty;
import org.jboss.seam.security.util.TypedBeanProperty;
import org.jboss.seam.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The default identity store implementation, uses JPA as its persistence mechanism.
 * 
 * @author Shane Bryzak
 */
public @ApplicationScoped @Transactional class JpaIdentityStore implements IdentityStore, Serializable
{
   private static final long serialVersionUID = 1171875389743972646L;

   protected FeatureSet featureSet;

   private Logger log = LoggerFactory.getLogger(JpaIdentityStore.class);
          
   @Inject Instance<EntityManager> entityManagerInstance;
   
   @Inject Instance<PasswordHash> passwordHashInstance;
   
   @Inject BeanManager manager;
  
   private Class<?> userEntityClass;
   private Class<?> roleEntityClass;
   private Class<?> xrefEntityClass;
   private TypedBeanProperty xrefUserProperty;
   private TypedBeanProperty xrefRoleProperty;
   
   private AnnotatedBeanProperty<UserPrincipal> userPrincipalProperty;
   private AnnotatedBeanProperty<UserPassword> userPasswordProperty;
   private AnnotatedBeanProperty<PasswordSalt> passwordSaltProperty;
   private AnnotatedBeanProperty<UserRoles> userRolesProperty;
   private AnnotatedBeanProperty<UserEnabled> userEnabledProperty;
   private AnnotatedBeanProperty<UserFirstName> userFirstNameProperty;
   private AnnotatedBeanProperty<UserLastName> userLastNameProperty;
   private AnnotatedBeanProperty<RoleName> roleNameProperty;
   private AnnotatedBeanProperty<RoleGroups> roleGroupsProperty;
   private AnnotatedBeanProperty<RoleConditional> roleConditionalProperty;
   
   public Set<Feature> getFeatures()
   {
      return featureSet.getFeatures();
   }
   
   public void setFeatures(Set<Feature> features)
   {
      featureSet = new FeatureSet(features);
   }
   
   public boolean supportsFeature(Feature feature)
   {
      return featureSet.supports(feature);
   }
   
   @Inject
   public void init()
   {      
      if (featureSet == null)
      {
         featureSet = new FeatureSet();
         featureSet.enableAll();
      }
      
      userPrincipalProperty = new AnnotatedBeanProperty<UserPrincipal>(getUserEntityClass(), UserPrincipal.class);
      userPasswordProperty = new AnnotatedBeanProperty<UserPassword>(getUserEntityClass(), UserPassword.class);
      passwordSaltProperty = new AnnotatedBeanProperty<PasswordSalt>(getUserEntityClass(), PasswordSalt.class);
      userRolesProperty = new AnnotatedBeanProperty<UserRoles>(getUserEntityClass(), UserRoles.class);
      userEnabledProperty = new AnnotatedBeanProperty<UserEnabled>(getUserEntityClass(), UserEnabled.class);
      userFirstNameProperty = new AnnotatedBeanProperty<UserFirstName>(getUserEntityClass(), UserFirstName.class);
      userLastNameProperty = new AnnotatedBeanProperty<UserLastName>(getUserEntityClass(), UserLastName.class);
             
      if (!userPrincipalProperty.isSet())
      {
         throw new IdentityManagementException("Invalid userClass " + getUserEntityClass().getName() +
               " - required annotation @UserPrincipal not found on any Field or Method.");
      }
      
      if (!userRolesProperty.isSet())
      {
         throw new IdentityManagementException("Invalid userClass " + getUserEntityClass().getName() +
         " - required annotation @UserRoles not found on any Field or Method.");
      }
      
      if (getRoleEntityClass() != null)
      {
         roleNameProperty = new AnnotatedBeanProperty<RoleName>(getRoleEntityClass(), RoleName.class);
         roleGroupsProperty = new AnnotatedBeanProperty<RoleGroups>(getRoleEntityClass(), RoleGroups.class);
         roleConditionalProperty = new AnnotatedBeanProperty<RoleConditional>(getRoleEntityClass(), RoleConditional.class);
         
         if (!roleNameProperty.isSet())
         {
            throw new IdentityManagementException("Invalid roleClass " + getRoleEntityClass().getName() +
            " - required annotation @RoleName not found on any Field or Method.");
         }
                 
         Type type = userRolesProperty.getPropertyType();
         if (type instanceof ParameterizedType &&
               Collection.class.isAssignableFrom((Class<?>) ((ParameterizedType) type).getRawType()))
         {
            Type genType = Object.class;

            for (Type t : ((ParameterizedType) type).getActualTypeArguments())
            {
               genType = t;
               break;
            }
         
            // If the @UserRoles property isn't a collection of <roleClass>, then assume the relationship
            // is going through a cross-reference table
            if (!genType.equals(getRoleEntityClass()))
            {
               xrefEntityClass = (Class<?>) genType;
               xrefUserProperty = new TypedBeanProperty(xrefEntityClass, getUserEntityClass());
               xrefRoleProperty = new TypedBeanProperty(xrefEntityClass, getRoleEntityClass());
               
               if (!xrefUserProperty.isSet())
               {
                  throw new IdentityManagementException("Error configuring JpaIdentityStore - it looks like " +
                        "you're using a cross-reference table, however the user property cannot be determined.");
               }
               
               if (!xrefRoleProperty.isSet())
               {
                  throw new IdentityManagementException("Error configuring JpaIdentityStore - it looks like " +
                  "you're using a cross-reference table, however the role property cannot be determined.");
               }
            }
         }
      }      
   }
   
   public boolean createUser(String username, String password, String firstname, String lastname)
   {
      try
      {
         if (getUserEntityClass() == null)
         {
            throw new IdentityManagementException("Could not create account, userClass not set");
         }
         
         if (userExists(username))
         {
            throw new IdentityManagementException("Could not create account, already exists");
         }
         
         Object user = getUserEntityClass().newInstance();

         getUserPrincipalProperty().setValue(user, username);

         if (getUserFirstNameProperty().isSet()) getUserFirstNameProperty().setValue(user, firstname);
         if (getUserLastNameProperty().isSet()) getUserLastNameProperty().setValue(user, lastname);
         
         if (password == null)
         {
            if (getUserEnabledProperty().isSet()) getUserEnabledProperty().setValue(user, false);
         }
         else
         {
            setUserPassword(user, password);
            if (getUserEnabledProperty().isSet()) getUserEnabledProperty().setValue(user, true);
         }
         
         manager.fireEvent(new PrePersistUserEvent(user));
         
         getEntityManager().persist(user);

         manager.fireEvent(new UserCreatedEvent(user));
         
         return true;
      }
      catch (Exception ex)
      {
         if (ex instanceof IdentityManagementException)
         {
            throw (IdentityManagementException) ex;
         }
         else
         {
            throw new IdentityManagementException("Could not create account", ex);
         }
      }
   }
   
   protected void setUserPassword(Object user, String password)
   {
      if (getPasswordSaltProperty().isSet())
      {
         byte[] salt = generateUserSalt(user);
         getPasswordSaltProperty().setValue(user, BinTools.bin2hex(salt));
         getUserPasswordProperty().setValue(user, generatePasswordHash(password, salt));
      }
      else
      {
         getUserPasswordProperty().setValue(user, generatePasswordHash(password, getUserAccountSalt(user)));
      }
   }
   
   /**
    * @deprecated Use JpaIdentityStore.generateRandomSalt(Object) instead
    */
   @Deprecated
   protected String getUserAccountSalt(Object user)
   {
      // By default, we'll use the user's username as the password salt
      return getUserPrincipalProperty().getValue(user).toString();
   }
   
   /**
    * Generates a 64 bit random salt value
    */
   public byte[] generateUserSalt(Object user)
   {
      return getPasswordHash().generateRandomSalt();
   }
   
   public boolean createUser(String username, String password)
   {
      return createUser(username, password, null, null);
   }
   
   public boolean deleteUser(String name)
   {
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("Could not delete, user '" + name + "' does not exist");
      }
      
      getEntityManager().remove(user);
      return true;
   }
   
   @SuppressWarnings("unchecked")
   public boolean grantRole(String username, String role)
   {
      if (getRoleEntityClass() == null) return false;
      
      Object user = lookupUser(username);
      if (user == null)
      {
         if (getUserPasswordProperty().isSet())
         {
            // If no userPasswordProperty is set, it means that authentication is being performed
            // by another identity store and this one is just managing roles
            throw new NoSuchUserException("Could not grant role, no such user '" + username + "'");
         }
         else
         {
            // We need to create a new user object
            if (createUser(username, null))
            {
               user = lookupUser(username);
            }
            else
            {
               throw new IdentityManagementException(
                     "Could not grant role - user does not exist and an attempt to create the user failed.");
            }
         }
      }
      
      Object roleToGrant = lookupRole(role);
      if (roleToGrant == null)
      {
         throw new NoSuchRoleException("Could not grant role, role '" + role + "' does not exist");
      }
      
      Collection<?> userRoles = (Collection<?>) getUserRolesProperty().getValue(user);
      if (userRoles == null)
      {
         Type propType = getUserRolesProperty().getPropertyType();
         Class<?> collectionType;
         
         if (propType instanceof Class && Collection.class.isAssignableFrom((Class<?>) propType))
         {
            collectionType = (Class<?>) propType;
         }
         else if (propType instanceof ParameterizedType &&
                  Collection.class.isAssignableFrom((Class<?>) ((ParameterizedType) propType).getRawType()))
         {
            collectionType = (Class<?>) ((ParameterizedType) propType).getRawType();
         }
         else
         {
            throw new IllegalStateException("Could not determine collection type for user roles.");
         }
         
         // This should either be a Set, or a List...
         if (Set.class.isAssignableFrom(collectionType))
         {
            userRoles = new HashSet<Object>();
         }
         else if (List.class.isAssignableFrom(collectionType))
         {
            userRoles = new ArrayList<Object>();
         }
         
         getUserRolesProperty().setValue(user, userRoles);
      }
      else if (((Collection<?>) getUserRolesProperty().getValue(user)).contains(roleToGrant))
      {
         return false;
      }

      if (getXrefEntityClass() == null)
      {
         // If this is a Many-To-Many relationship, simply add the role
         ((Collection<Object>) getUserRolesProperty().getValue(user)).add(roleToGrant);
      }
      else
      {
         // Otherwise we need to insert a cross-reference entity instance
         try
         {
            Object xref = getXrefEntityClass().newInstance();
            getXrefUserProperty().setValue(xref, user);
            getXrefRoleProperty().setValue(xref, roleToGrant);
            
            manager.fireEvent(new PrePersistUserRoleEvent(xref));
            
            ((Collection<Object>) getUserRolesProperty().getValue(user)).add(getEntityManager().merge(xref));
         }
         catch (Exception ex)
         {
            throw new IdentityManagementException("Error creating cross-reference role record.", ex);
         }
      }
      
      return true;
   }
   
   public boolean revokeRole(String username, String role)
   {
      Object user = lookupUser(username);
      if (user == null)
      {
         throw new NoSuchUserException("Could not revoke role, no such user '" + username + "'");
      }
      
      Object roleToRevoke = lookupRole(role);
      if (roleToRevoke == null)
      {
         throw new NoSuchRoleException("Could not revoke role, role '" + role + "' does not exist");
      }
             
      boolean success = false;
      
      if (getXrefEntityClass() == null)
      {
         success = ((Collection<?>) getUserRolesProperty().getValue(user)).remove(roleToRevoke);
      }
      else
      {
         Collection<?> roles = ((Collection<?>) getUserRolesProperty().getValue(user));

         for (Object xref : roles)
         {
            if (getXrefRoleProperty().getValue(xref).equals(roleToRevoke))
            {
               success = roles.remove(xref);
               break;
            }
         }
      }

      return success;
   }
   
   @SuppressWarnings("unchecked")
   public boolean addRoleToGroup(String role, String group)
   {
      if (!getRoleGroupsProperty().isSet()) return false;
      
      Object targetRole = lookupRole(role);
      if (targetRole == null)
      {
         throw new NoSuchUserException("Could not add role to group, no such role '" + role + "'");
      }
      
      Object targetGroup = lookupRole(group);
      if (targetGroup == null)
      {
         throw new NoSuchRoleException("Could not grant role, group '" + group + "' does not exist");
      }
      
      Collection<?> roleGroups = (Collection<?>) getRoleGroupsProperty().getValue(targetRole);
      if (roleGroups == null)
      {
         // This should either be a Set, or a List...
         Class<?> rawType = null;
         if (getRoleGroupsProperty().getPropertyType() instanceof ParameterizedType)
         {
            rawType = (Class<?>) ((ParameterizedType) getRoleGroupsProperty().getPropertyType()).getRawType();
         }
         else
         {
            return false;
         }
          
         if (Set.class.isAssignableFrom(rawType))
         {
            roleGroups = new HashSet<Object>();
         }
         else if (List.class.isAssignableFrom(rawType))
         {
            roleGroups = new ArrayList<Object>();
         }
         
         getRoleGroupsProperty().setValue(targetRole, roleGroups);
      }
      else if (((Collection<?>) getRoleGroupsProperty().getValue(targetRole)).contains(targetGroup))
      {
         return false;
      }

      ((Collection<Object>) getRoleGroupsProperty().getValue(targetRole)).add(targetGroup);
      
      return true;
   }

   public boolean removeRoleFromGroup(String role, String group)
   {
      if (!getRoleGroupsProperty().isSet()) return false;
      
      Object roleToRemove = lookupRole(role);
      if (role == null)
      {
         throw new NoSuchUserException("Could not remove role from group, no such role '" + role + "'");
      }
      
      Object targetGroup = lookupRole(group);
      if (targetGroup == null)
      {
         throw new NoSuchRoleException("Could not remove role from group, no such group '" + group + "'");
      }
       
      boolean success = ((Collection<?>) getRoleGroupsProperty().getValue(roleToRemove)).remove(targetGroup);
      
      return success;
   }
   
   public boolean createRole(String role)
   {
      try
      {
         if (getRoleEntityClass() == null)
         {
            throw new IdentityManagementException("Could not create role, roleClass not set");
         }
         
         if (roleExists(role))
         {
            throw new IdentityManagementException("Could not create role, already exists");
         }
         
         Object instance = getRoleEntityClass().newInstance();
         getRoleNameProperty().setValue(instance, role);
         getEntityManager().persist(instance);
         
         return true;
      }
      catch (Exception ex)
      {
         if (ex instanceof IdentityManagementException)
         {
            throw (IdentityManagementException) ex;
         }
         else
         {
            throw new IdentityManagementException("Could not create role", ex);
         }
      }
   }
   
   public boolean deleteRole(String role)
   {
      Object roleToDelete = lookupRole(role);
      if (roleToDelete == null)
      {
         throw new NoSuchRoleException("Could not delete role, role '" + role + "' does not exist");
      }
      
      if (getXrefEntityClass() != null)
      {
         getEntityManager().createQuery("delete " + getXrefEntityClass().getName() + " where role = :role")
         .setParameter("role", roleToDelete)
         .executeUpdate();
      }
      else
      {
         List<String> users = listUserMembers(role);
         for (String user : users)
         {
            revokeRole(user, role);
         }
      }
      
      List<String> roles = listRoleMembers(role);
      for (String r : roles)
      {
         removeRoleFromGroup(r, role);
      }
            
      getEntityManager().remove(roleToDelete);
      return true;
   }
   
   public boolean enableUser(String name)
   {
      if (!getUserEnabledProperty().isSet())
      {
         log.debug("Can not enable user, no @UserEnabled property configured in userClass " +
               getUserEntityClass().getName());
         return false;
      }
      
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("Could not enable user, user '" + name + "' does not exist");
      }
      
      // Can't enable an already-enabled user, return false
      if (((Boolean) getUserEnabledProperty().getValue(user)) == true)
      {
         return false;
      }
      
      getUserEnabledProperty().setValue(user, true);
      return true;
   }
   
   public boolean disableUser(String name)
   {
      if (!getUserEnabledProperty().isSet())
      {
         log.debug("Can not disable user, no @UserEnabled property configured in userClass " +
               getUserEntityClass().getName());
         return false;
      }
      
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("Could not disable user, user '" + name + "' does not exist");
      }
      
      // Can't disable an already-disabled user, return false
      if (((Boolean) getUserEnabledProperty().getValue(user)) == false)
      {
         return false;
      }
      
      getUserEnabledProperty().setValue(user, false);
      return true;
   }
   
   public boolean changePassword(String username, String password)
   {
      Object user = lookupUser(username);
      if (user == null)
      {
         throw new NoSuchUserException("Could not change password, user '" + username + "' does not exist");
      }
      
      setUserPassword(user, password);
      
      return true;
   }
   
   public boolean userExists(String name)
   {
      return lookupUser(name) != null;
   }
   
   public boolean roleExists(String name)
   {
      return lookupRole(name) != null;
   }
   
   public boolean isUserEnabled(String name)
   {
      Object user = lookupUser(name);
      return user != null && (!getUserEnabledProperty().isSet() ||
            (((Boolean) getUserEnabledProperty().getValue(user))) == true);
   }
   
   public List<String> getGrantedRoles(String name)
   {
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("No such user '" + name + "'");
      }

      List<String> roles = new ArrayList<String>();
      
      Collection<?> userRoles = (Collection<?>) getUserRolesProperty().getValue(user);
      if (userRoles != null)
      {
         for (Object role : userRoles)
         {
            if (getXrefEntityClass() == null)
            {
               roles.add((String) getRoleNameProperty().getValue(role));
            }
            else
            {
               Object xref = getRoleNameProperty().getValue(role);
               Object userRole = getXrefRoleProperty().getValue(xref);
               roles.add((String) getRoleNameProperty().getValue(userRole));
            }
         }
      }
      
      return roles;
   }
   
   public List<String> getRoleGroups(String name)
   {
      Object role = lookupRole(name);
      if (role == null)
      {
         throw new NoSuchUserException("No such role '" + name + "'");
      }

      List<String> groups = new ArrayList<String>();
      
      if (getRoleGroupsProperty().isSet())
      {
         Collection<?> roleGroups = (Collection<?>) getRoleGroupsProperty().getValue(role);
         if (roleGroups != null)
         {
            for (Object group : roleGroups)
            {
               groups.add((String) getRoleNameProperty().getValue(group));
            }
         }
      }
      
      return groups;
   }
   
   public List<String> getImpliedRoles(String name)
   {
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("No such user '" + name + "'");
      }

      Set<String> roles = new HashSet<String>();
      Collection<?> userRoles = (Collection<?>) getUserRolesProperty().getValue(user);
      if (userRoles != null)
      {
         for (Object role : userRoles)
         {
            addRoleAndMemberships((String) getRoleNameProperty().getValue(role), roles);
         }
      }
      
      return new ArrayList<String>(roles);
   }
   
   private void addRoleAndMemberships(String role, Set<String> roles)
   {
      if (roles.add(role))
      {
         Object instance = lookupRole(role);
         
         if (getRoleGroupsProperty().isSet())
         {
            Collection<?> groups = (Collection<?>) getRoleGroupsProperty().getValue(instance);
            
            if (groups != null)
            {
               for (Object group : groups)
               {
                  addRoleAndMemberships((String) getRoleNameProperty().getValue(group), roles);
               }
            }
         }
      }
   }
   
   public String generatePasswordHash(String password, byte[] salt)
   {
      if (getPasswordSaltProperty().isSet())
      {
         try
         {
            return getPasswordHash().createPasswordKey(password.toCharArray(), salt,
                  getUserPasswordProperty().getAnnotation().iterations());
         }
         catch (GeneralSecurityException ex)
         {
            throw new IdentityManagementException("Exception generating password hash", ex);
         }
      }
      else
      {
         return generatePasswordHash(password, new String(salt));
      }
   }
   
   /**
    * 
    * @deprecated Use JpaIdentityStore.generatePasswordHash(String, byte[]) instead
    */
   @Deprecated
   protected String generatePasswordHash(String password, String salt)
   {
      String algorithm = getUserPasswordProperty().getAnnotation().hash();
      
      if (algorithm == null || "".equals(algorithm))
      {
         if (salt == null || "".equals(salt))
         {
            return getPasswordHash().generateHash(password);
         }
         else
         {
            return getPasswordHash().generateSaltedHash(password, salt);
         }
      }
      else if ("none".equalsIgnoreCase(algorithm))
      {
         return password;
      }
      else
      {
         if (salt == null || "".equals(salt))
         {
            return getPasswordHash().generateHash(password, algorithm);
         }
         else
         {
            return getPasswordHash().generateSaltedHash(password, salt, algorithm);
         }
      }
   }
   
   public boolean authenticate(String username, String password)
   {
      Object user = lookupUser(username);
      if (user == null || (getUserEnabledProperty().isSet() &&
            ((Boolean) getUserEnabledProperty().getValue(user) == false)))
      {
         return false;
      }
      
      String passwordHash = null;
      
      if (getPasswordSaltProperty().isSet())
      {
         String encodedSalt = (String) getPasswordSaltProperty().getValue(user);
         if (encodedSalt == null)
         {
            throw new IdentityManagementException("A @PasswordSalt property was found on entity " + user +
                  ", but it contains no value");
         }
         
         passwordHash = generatePasswordHash(password, BinTools.hex2bin(encodedSalt));
      }
      else
      {
         passwordHash = generatePasswordHash(password, getUserAccountSalt(user));
      }
      
       
      boolean success = passwordHash.equals(getUserPasswordProperty().getValue(user));
            
      if (success)
      {
         manager.fireEvent(new UserAuthenticatedEvent(user));
      }
      
      return success;
   }
   
   public Object lookupUser(String username)
   {
      try
      {
         Object user = getEntityManager().createQuery(
            "select u from " + getUserEntityClass().getName() + " u where u." +
            getUserPrincipalProperty().getName() + " = :username")
            .setParameter("username", username)
            .getSingleResult();
         
         return user;
      }
      catch (NoResultException ex)
      {
         return null;
      }
   }
   
   public String getUserName(Object user)
   {
      return (String) getUserPrincipalProperty().getValue(user);
   }
   
   public String getRoleName(Object role)
   {
      return (String) getRoleNameProperty().getValue(role);
   }
   
   public boolean isRoleConditional(String role)
   {
      return getRoleConditionalProperty().isSet() ? (Boolean) getRoleConditionalProperty().getValue(
            lookupRole(role)) : false;
   }
   
   public Object lookupRole(String role)
   {
      try
      {
         Object value = getEntityManager().createQuery(
            "select r from " + getRoleEntityClass().getName() + " r where " + getRoleNameProperty().getName() +
            " = :role")
            .setParameter("role", role)
            .getSingleResult();
         
         return value;
      }
      catch (NoResultException ex)
      {
         return null;
      }
   }
   
   @SuppressWarnings("unchecked")
   public List<String> listUsers()
   {
      return getEntityManager().createQuery(
            "select u." + getUserPrincipalProperty().getName() + " from " +
            getUserEntityClass().getName() + " u")
            .getResultList();
   }
   
   @SuppressWarnings("unchecked")
   public List<String> listUsers(String filter)
   {
      return getEntityManager().createQuery(
            "select u." + getUserPrincipalProperty().getName() + " from " + getUserEntityClass().getName() +
            " u where lower(" + getUserPrincipalProperty().getName() + ") like :username")
            .setParameter("username", "%" + (filter != null ? filter.toLowerCase() : "") +
                  "%")
            .getResultList();
   }

   @SuppressWarnings("unchecked")
   public List<String> listRoles()
   {
      return getEntityManager().createQuery(
            "select r." + getRoleNameProperty().getName() + " from " +
            getRoleEntityClass().getName() + " r").getResultList();
   }
   
   public List<Principal> listMembers(String role)
   {
      List<Principal> members = new ArrayList<Principal>();
      
      for (String user : listUserMembers(role))
      {
         members.add(new SimplePrincipal(user));
      }
      
      for (String roleName : listRoleMembers(role))
      {
         members.add(new Role(roleName));
      }
      
      return members;
   }
   
   @SuppressWarnings("unchecked")
   private List<String> listUserMembers(String role)
   {
      Object roleEntity = lookupRole(role);

      if (getXrefEntityClass() == null)
      {
         return getEntityManager().createQuery("select u." +
               getUserPrincipalProperty().getName() +
               " from " + getUserEntityClass().getName() + " u where :role member of u." +
               getUserRolesProperty().getName())
               .setParameter("role", roleEntity)
               .getResultList();
      }
      else
      {
         List<?> xrefs = getEntityManager().createQuery("select x from " +
               getXrefEntityClass().getName() + " x where x." +
               getXrefRoleProperty().getName() + " = :role")
               .setParameter("role", roleEntity)
               .getResultList();

         List<String> members = new ArrayList<String>();
         
         for (Object xref : xrefs)
         {
            Object user = getXrefUserProperty().getValue(xref);
            members.add(getUserPrincipalProperty().getValue(user).toString());
         }
         
         return members;
      }
     
   }
   
   @SuppressWarnings("unchecked")
   private List<String> listRoleMembers(String role)
   {
      if (getRoleGroupsProperty().isSet())
      {
         Object roleEntity = lookupRole(role);
         
         return getEntityManager().createQuery("select r." +
               getRoleNameProperty().getName() +
               " from " + getRoleEntityClass().getName() + " r where :role member of r." +
               getRoleGroupsProperty().getName())
               .setParameter("role", roleEntity)
               .getResultList();
      }
      
      return null;
   }
   
   @SuppressWarnings("unchecked")
   public List<String> listGrantableRoles()
   {
      StringBuilder roleQuery = new StringBuilder();
      
      roleQuery.append("select r.");
      roleQuery.append(getRoleNameProperty().getName());
      roleQuery.append(" from ");
      roleQuery.append(getRoleEntityClass().getName());
      roleQuery.append(" r");
      
      if (getRoleConditionalProperty().isSet())
      {
         roleQuery.append(" where r.");
         roleQuery.append(getRoleConditionalProperty().getName());
         roleQuery.append(" = false");
      }
      
      return getEntityManager().createQuery(roleQuery.toString()).getResultList();
   }
   
   protected EntityManager getEntityManager()
   {
      EntityManager em = entityManagerInstance.get();
      em.joinTransaction();
      return em;
   }
   
   protected PasswordHash getPasswordHash()
   {
      return passwordHashInstance.get();
   }
   
   public Class<?> getUserEntityClass()
   {     
      return userEntityClass;
   }
   
   public void setUserEntityClass(Class<?> userEntityClass)
   {
      this.userEntityClass = userEntityClass;
   }
   
   public Class<?> getRoleEntityClass()
   {      
      return roleEntityClass;
   }
   
   public void setRoleEntityClass(Class<?> roleEntityClass)
   {
      this.roleEntityClass = roleEntityClass;
   }
   
   public Class<?> getXrefEntityClass()
   {
      return xrefEntityClass;
   }
   
   public TypedBeanProperty getXrefUserProperty()
   {
      return xrefUserProperty;
   }
   
   public TypedBeanProperty getXrefRoleProperty()
   {
      return xrefRoleProperty;
   }
   
   public AnnotatedBeanProperty<UserPrincipal> getUserPrincipalProperty()
   {
      return userPrincipalProperty;
   }
   
   public AnnotatedBeanProperty<UserPassword> getUserPasswordProperty()
   {
      return userPasswordProperty;
   }
   
   public AnnotatedBeanProperty<PasswordSalt> getPasswordSaltProperty() {
      return passwordSaltProperty;
   }
   
   public AnnotatedBeanProperty<UserRoles> getUserRolesProperty() {
      return userRolesProperty;
   }
   
   public AnnotatedBeanProperty<UserEnabled> getUserEnabledProperty() {
      return userEnabledProperty;
   }
   
   public AnnotatedBeanProperty<UserFirstName> getUserFirstNameProperty() {
      return userFirstNameProperty;
   }
   
   public AnnotatedBeanProperty<UserLastName> getUserLastNameProperty() {
      return userLastNameProperty;
   }
      
   public AnnotatedBeanProperty<RoleName> getRoleNameProperty() {
      return roleNameProperty;
   }
   
   public AnnotatedBeanProperty<RoleGroups> getRoleGroupsProperty() {
      return roleGroupsProperty;
   }
   
   public AnnotatedBeanProperty<RoleConditional> getRoleConditionalProperty() {
      return roleConditionalProperty;
   }   
}
