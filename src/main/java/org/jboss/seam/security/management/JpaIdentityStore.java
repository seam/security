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

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

import org.jboss.seam.security.Role;
import org.jboss.seam.security.SimplePrincipal;
import org.jboss.seam.security.crypto.BinTools;
import org.jboss.seam.security.events.PrePersistUserEvent;
import org.jboss.seam.security.events.PrePersistUserRoleEvent;
import org.jboss.seam.security.events.UserAuthenticatedEvent;
import org.jboss.seam.security.events.UserCreatedEvent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The default identity store implementation, uses JPA as its persistence mechanism.
 * 
 * @author Shane Bryzak
 */
@RequestScoped
public class JpaIdentityStore implements IdentityStore, Serializable
{
   private static final long serialVersionUID = 1171875389743972646L;

   protected FeatureSet featureSet;

   private Logger log = LoggerFactory.getLogger(JpaIdentityStore.class);
          
   @PersistenceContext EntityManager entityManager;
   
   @Inject Instance<PasswordHash> passwordHashInstance;
  
   private JpaIdentityStoreConfig config;
   private BeanManager manager;
   
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
   public void init(JpaIdentityStoreConfig config, BeanManager manager)
   {
      this.config = config;
      this.manager = manager;
      
      if (featureSet == null)
      {
         featureSet = new FeatureSet();
         featureSet.enableAll();
      }
      
      if (config.getUserEntityClass() == null)
      {
         log.error("Error in JpaIdentityStore configuration - userClass must be configured.");
         return;
      }
   }
   
   public boolean createUser(String username, String password, String firstname, String lastname)
   {
      try
      {
         if (config.getUserEntityClass() == null)
         {
            throw new IdentityManagementException("Could not create account, userClass not set");
         }
         
         if (userExists(username))
         {
            throw new IdentityManagementException("Could not create account, already exists");
         }
         
         Object user = config.getUserEntityClass().newInstance();

         config.getUserPrincipalProperty().setValue(user, username);

         if (config.getUserFirstNameProperty().isSet()) config.getUserFirstNameProperty().setValue(user, firstname);
         if (config.getUserLastNameProperty().isSet()) config.getUserLastNameProperty().setValue(user, lastname);
         
         if (password == null)
         {
            if (config.getUserEnabledProperty().isSet()) config.getUserEnabledProperty().setValue(user, false);
         }
         else
         {
            setUserPassword(user, password);
            if (config.getUserEnabledProperty().isSet()) config.getUserEnabledProperty().setValue(user, true);
         }
         
         manager.fireEvent(new PrePersistUserEvent(user));
         
         entityManager.persist(user);

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
      if (config.getPasswordSaltProperty().isSet())
      {
         byte[] salt = generateUserSalt(user);
         config.getPasswordSaltProperty().setValue(user, BinTools.bin2hex(salt));
         config.getUserPasswordProperty().setValue(user, generatePasswordHash(password, salt));
      }
      else
      {
         config.getUserPasswordProperty().setValue(user, generatePasswordHash(password, getUserAccountSalt(user)));
      }
   }
   
   /**
    * @deprecated Use JpaIdentityStore.generateRandomSalt(Object) instead
    */
   @Deprecated
   protected String getUserAccountSalt(Object user)
   {
      // By default, we'll use the user's username as the password salt
      return config.getUserPrincipalProperty().getValue(user).toString();
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
      
      entityManager.remove(user);
      return true;
   }
   
   @SuppressWarnings("unchecked")
   public boolean grantRole(String username, String role)
   {
      if (config.getRoleEntityClass() == null) return false;
      
      Object user = lookupUser(username);
      if (user == null)
      {
         if (config.getUserPasswordProperty().isSet())
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
      
      Collection<?> userRoles = (Collection<?>) config.getUserRolesProperty().getValue(user);
      if (userRoles == null)
      {
         Type propType = config.getUserRolesProperty().getPropertyType();
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
         
         config.getUserRolesProperty().setValue(user, userRoles);
      }
      else if (((Collection<?>) config.getUserRolesProperty().getValue(user)).contains(roleToGrant))
      {
         return false;
      }

      if (config.getXrefEntityClass() == null)
      {
         // If this is a Many-To-Many relationship, simply add the role
         ((Collection<Object>) config.getUserRolesProperty().getValue(user)).add(roleToGrant);
      }
      else
      {
         // Otherwise we need to insert a cross-reference entity instance
         try
         {
            Object xref = config.getXrefEntityClass().newInstance();
            config.getXrefUserProperty().setValue(xref, user);
            config.getXrefRoleProperty().setValue(xref, roleToGrant);
            
            manager.fireEvent(new PrePersistUserRoleEvent(xref));
            
            ((Collection<Object>) config.getUserRolesProperty().getValue(user)).add(entityManager.merge(xref));
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
      
      if (config.getXrefEntityClass() == null)
      {
         success = ((Collection<?>) config.getUserRolesProperty().getValue(user)).remove(roleToRevoke);
      }
      else
      {
         Collection<?> roles = ((Collection<?>) config.getUserRolesProperty().getValue(user));

         for (Object xref : roles)
         {
            if (config.getXrefRoleProperty().getValue(xref).equals(roleToRevoke))
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
      if (!config.getRoleGroupsProperty().isSet()) return false;
      
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
      
      Collection<?> roleGroups = (Collection<?>) config.getRoleGroupsProperty().getValue(targetRole);
      if (roleGroups == null)
      {
         // This should either be a Set, or a List...
         Class<?> rawType = null;
         if (config.getRoleGroupsProperty().getPropertyType() instanceof ParameterizedType)
         {
            rawType = (Class<?>) ((ParameterizedType) config.getRoleGroupsProperty().getPropertyType()).getRawType();
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
         
         config.getRoleGroupsProperty().setValue(targetRole, roleGroups);
      }
      else if (((Collection<?>) config.getRoleGroupsProperty().getValue(targetRole)).contains(targetGroup))
      {
         return false;
      }

      ((Collection<Object>) config.getRoleGroupsProperty().getValue(targetRole)).add(targetGroup);
      
      return true;
   }

   public boolean removeRoleFromGroup(String role, String group)
   {
      if (!config.getRoleGroupsProperty().isSet()) return false;
      
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
       
      boolean success = ((Collection<?>) config.getRoleGroupsProperty().getValue(roleToRemove)).remove(targetGroup);
      
      return success;
   }
   
   public boolean createRole(String role)
   {
      try
      {
         if (config.getRoleEntityClass() == null)
         {
            throw new IdentityManagementException("Could not create role, roleClass not set");
         }
         
         if (roleExists(role))
         {
            throw new IdentityManagementException("Could not create role, already exists");
         }
         
         Object instance = config.getRoleEntityClass().newInstance();
         config.getRoleNameProperty().setValue(instance, role);
         entityManager.persist(instance);
         
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
      
      if (config.getXrefEntityClass() != null)
      {
         entityManager.createQuery("delete " + config.getXrefEntityClass().getName() + " where role = :role")
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
            
      entityManager.remove(roleToDelete);
      return true;
   }
   
   public boolean enableUser(String name)
   {
      if (!config.getUserEnabledProperty().isSet())
      {
         log.debug("Can not enable user, no @UserEnabled property configured in userClass " +
               config.getUserEntityClass().getName());
         return false;
      }
      
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("Could not enable user, user '" + name + "' does not exist");
      }
      
      // Can't enable an already-enabled user, return false
      if (((Boolean) config.getUserEnabledProperty().getValue(user)) == true)
      {
         return false;
      }
      
      config.getUserEnabledProperty().setValue(user, true);
      return true;
   }
   
   public boolean disableUser(String name)
   {
      if (!config.getUserEnabledProperty().isSet())
      {
         log.debug("Can not disable user, no @UserEnabled property configured in userClass " +
               config.getUserEntityClass().getName());
         return false;
      }
      
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("Could not disable user, user '" + name + "' does not exist");
      }
      
      // Can't disable an already-disabled user, return false
      if (((Boolean) config.getUserEnabledProperty().getValue(user)) == false)
      {
         return false;
      }
      
      config.getUserEnabledProperty().setValue(user, false);
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
      return user != null && (!config.getUserEnabledProperty().isSet() ||
            (((Boolean) config.getUserEnabledProperty().getValue(user))) == true);
   }
   
   public List<String> getGrantedRoles(String name)
   {
      Object user = lookupUser(name);
      if (user == null)
      {
         throw new NoSuchUserException("No such user '" + name + "'");
      }

      List<String> roles = new ArrayList<String>();
      
      Collection<?> userRoles = (Collection<?>) config.getUserRolesProperty().getValue(user);
      if (userRoles != null)
      {
         for (Object role : userRoles)
         {
            if (config.getXrefEntityClass() == null)
            {
               roles.add((String) config.getRoleNameProperty().getValue(role));
            }
            else
            {
               Object xref = config.getRoleNameProperty().getValue(role);
               Object userRole = config.getXrefRoleProperty().getValue(xref);
               roles.add((String) config.getRoleNameProperty().getValue(userRole));
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
      
      if (config.getRoleGroupsProperty().isSet())
      {
         Collection<?> roleGroups = (Collection<?>) config.getRoleGroupsProperty().getValue(role);
         if (roleGroups != null)
         {
            for (Object group : roleGroups)
            {
               groups.add((String) config.getRoleNameProperty().getValue(group));
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
      Collection<?> userRoles = (Collection<?>) config.getUserRolesProperty().getValue(user);
      if (userRoles != null)
      {
         for (Object role : userRoles)
         {
            addRoleAndMemberships((String) config.getRoleNameProperty().getValue(role), roles);
         }
      }
      
      return new ArrayList<String>(roles);
   }
   
   private void addRoleAndMemberships(String role, Set<String> roles)
   {
      if (roles.add(role))
      {
         Object instance = lookupRole(role);
         
         if (config.getRoleGroupsProperty().isSet())
         {
            Collection<?> groups = (Collection<?>) config.getRoleGroupsProperty().getValue(instance);
            
            if (groups != null)
            {
               for (Object group : groups)
               {
                  addRoleAndMemberships((String) config.getRoleNameProperty().getValue(group), roles);
               }
            }
         }
      }
   }
   
   public String generatePasswordHash(String password, byte[] salt)
   {
      if (config.getPasswordSaltProperty().isSet())
      {
         try
         {
            return getPasswordHash().createPasswordKey(password.toCharArray(), salt,
                  config.getUserPasswordProperty().getAnnotation().iterations());
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
      String algorithm = config.getUserPasswordProperty().getAnnotation().hash();
      
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
      if (user == null || (config.getUserEnabledProperty().isSet() &&
            ((Boolean) config.getUserEnabledProperty().getValue(user) == false)))
      {
         return false;
      }
      
      String passwordHash = null;
      
      if (config.getPasswordSaltProperty().isSet())
      {
         String encodedSalt = (String) config.getPasswordSaltProperty().getValue(user);
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
      
       
      boolean success = passwordHash.equals(config.getUserPasswordProperty().getValue(user));
            
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
         Object user = entityManager.createQuery(
            "select u from " + config.getUserEntityClass().getName() + " u where " +
            config.getUserPrincipalProperty().getName() + " = :username")
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
      return (String) config.getUserPrincipalProperty().getValue(user);
   }
   
   public String getRoleName(Object role)
   {
      return (String) config.getRoleNameProperty().getValue(role);
   }
   
   public boolean isRoleConditional(String role)
   {
      return config.getRoleConditionalProperty().isSet() ? (Boolean) config.getRoleConditionalProperty().getValue(
            lookupRole(role)) : false;
   }
   
   public Object lookupRole(String role)
   {
      try
      {
         Object value = entityManager.createQuery(
            "select r from " + config.getRoleEntityClass().getName() + " r where " + config.getRoleNameProperty().getName() +
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
      return entityManager.createQuery(
            "select u." + config.getUserPrincipalProperty().getName() + " from " +
            config.getUserEntityClass().getName() + " u")
            .getResultList();
   }
   
   @SuppressWarnings("unchecked")
   public List<String> listUsers(String filter)
   {
      return entityManager.createQuery(
            "select u." + config.getUserPrincipalProperty().getName() + " from " + config.getUserEntityClass().getName() +
            " u where lower(" + config.getUserPrincipalProperty().getName() + ") like :username")
            .setParameter("username", "%" + (filter != null ? filter.toLowerCase() : "") +
                  "%")
            .getResultList();
   }

   @SuppressWarnings("unchecked")
   public List<String> listRoles()
   {
      return entityManager.createQuery(
            "select r." + config.getRoleNameProperty().getName() + " from " +
            config.getRoleEntityClass().getName() + " r").getResultList();
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

      if (config.getXrefEntityClass() == null)
      {
         return entityManager.createQuery("select u." +
               config.getUserPrincipalProperty().getName() +
               " from " + config.getUserEntityClass().getName() + " u where :role member of u." +
               config.getUserRolesProperty().getName())
               .setParameter("role", roleEntity)
               .getResultList();
      }
      else
      {
         List<?> xrefs = entityManager.createQuery("select x from " +
               config.getXrefEntityClass().getName() + " x where x." +
               config.getXrefRoleProperty().getName() + " = :role")
               .setParameter("role", roleEntity)
               .getResultList();

         List<String> members = new ArrayList<String>();
         
         for (Object xref : xrefs)
         {
            Object user = config.getXrefUserProperty().getValue(xref);
            members.add(config.getUserPrincipalProperty().getValue(user).toString());
         }
         
         return members;
      }
     
   }
   
   @SuppressWarnings("unchecked")
   private List<String> listRoleMembers(String role)
   {
      if (config.getRoleGroupsProperty().isSet())
      {
         Object roleEntity = lookupRole(role);
         
         return entityManager.createQuery("select r." +
               config.getRoleNameProperty().getName() +
               " from " + config.getRoleEntityClass().getName() + " r where :role member of r." +
               config.getRoleGroupsProperty().getName())
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
      roleQuery.append(config.getRoleNameProperty().getName());
      roleQuery.append(" from ");
      roleQuery.append(config.getRoleEntityClass().getName());
      roleQuery.append(" r");
      
      if (config.getRoleConditionalProperty().isSet())
      {
         roleQuery.append(" where r.");
         roleQuery.append(config.getRoleConditionalProperty().getName());
         roleQuery.append(" = false");
      }
      
      return entityManager.createQuery(roleQuery.toString()).getResultList();
   }
   
   protected PasswordHash getPasswordHash()
   {
      return passwordHashInstance.get();
   }
}
