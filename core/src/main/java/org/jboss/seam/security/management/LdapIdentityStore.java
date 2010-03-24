package org.jboss.seam.security.management;

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An IdentityStore implementation that integrates with a directory service.
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class LdapIdentityStore implements IdentityStore, Serializable
{
   private static final long serialVersionUID = 1854090869689846220L;
   
   // constants for LDAP syntax 1.3.6.1.4.1.1466.115.121.1.7 (boolean)
   private static final String LDAP_BOOLEAN_TRUE = "TRUE";
   private static final String LDAP_BOOLEAN_FALSE = "FALSE";
   
   private Logger log = LoggerFactory.getLogger(LdapIdentityStore.class);
   
   protected FeatureSet featureSet = new FeatureSet();
   
   private String serverAddress = "localhost";
   
   private int serverPort = 389;
   
   private String userContextDN = "ou=Person,dc=acme,dc=com";
      
   private String userDNPrefix = "uid=";
   
   private String userDNSuffix = ",ou=Person,dc=acme,dc=com";
   
   private String roleContextDN = "ou=Role,dc=acme,dc=com";
   
   private String roleDNPrefix = "cn=";
   
   private String roleDNSuffix = ",ou=Roles,dc=acme,dc=com";
   
   private String bindDN = "cn=Manager,dc=acme,dc=com";
   
   private String bindCredentials = "secret";
   
   private String userRoleAttribute = "roles";
   
   private boolean roleAttributeIsDN = true;
   
   private String userNameAttribute = "uid";
   
   private String userPasswordAttribute = "userPassword";
   
   private String firstNameAttribute = null;
   
   private String lastNameAttribute = "sn";
   
   private String fullNameAttribute = "cn";
   
   private String enabledAttribute = null;
   
   private String roleNameAttribute = "cn";
   
   private String objectClassAttribute = "objectClass";
   
   private String[] roleObjectClasses = { "organizationalRole" };
   
   private String[] userObjectClasses = { "person", "uidObject" };
   
   private int searchScope = SearchControls.SUBTREE_SCOPE;
   
   /**
    * Time limit for LDAP searches, in milliseconds
    */
   private int searchTimeLimit = 10000;
      
   public String getServerAddress()
   {
      return serverAddress;
   }
   
   public void setServerAddress(String serverAddress)
   {
      this.serverAddress = serverAddress;
   }
   
   public int getServerPort()
   {
      return serverPort;
   }
   
   public void setServerPort(int serverPort)
   {
      this.serverPort = serverPort;
   }
   
   public String getUserContextDN()
   {
      return userContextDN;
   }
   
   public void setUserContextDN(String userContextDN)
   {
      this.userContextDN = userContextDN;
   }
   
   public String getRoleContextDN()
   {
      return roleContextDN;
   }
   
   public void setRoleContextDN(String roleContextDN)
   {
      this.roleContextDN = roleContextDN;
   }
   
   public String getUserDNPrefix()
   {
      return userDNPrefix;
   }
   
   public void setUserDNPrefix(String value)
   {
      this.userDNPrefix = value;
   }
   
   public String getUserDNSuffix()
   {
      return userDNSuffix;
   }
   
   public void setUserDNSuffix(String value)
   {
      this.userDNSuffix = value;
   }

   public String getRoleDNPrefix()
   {
      return roleDNPrefix;
   }
   
   public void setRoleDNPrefix(String value)
   {
      this.roleDNPrefix = value;
   }
   
   public String getRoleDNSuffix()
   {
      return roleDNSuffix;
   }
   
   public void setRoleDNSuffix(String value)
   {
      this.roleDNSuffix = value;
   }
   
   public String getBindDN()
   {
      return bindDN;
   }
   
   public void setBindDN(String bindDN)
   {
      this.bindDN = bindDN;
   }
   
   public String getBindCredentials()
   {
      return bindCredentials;
   }
   
   public void setBindCredentials(String bindCredentials)
   {
      this.bindCredentials = bindCredentials;
   }
   
   public String getUserRoleAttribute()
   {
      return userRoleAttribute;
   }
   
   public void setUserRoleAttribute(String userRoleAttribute)
   {
      this.userRoleAttribute = userRoleAttribute;
   }
   
   public boolean getRoleAttributeIsDN()
   {
      return roleAttributeIsDN;
   }
   
   public void setRoleAttributeIsDN(boolean value)
   {
      this.roleAttributeIsDN = value;
   }
   
   public String getRoleNameAttribute()
   {
      return roleNameAttribute;
   }
   
   public void setRoleNameAttribute(String roleNameAttribute)
   {
      this.roleNameAttribute = roleNameAttribute;
   }
   
   public String getUserNameAttribute()
   {
      return userNameAttribute;
   }
   
   public void setUserNameAttribute(String userNameAttribute)
   {
      this.userNameAttribute = userNameAttribute;
   }
   
   public String getUserPasswordAttribute()
   {
      return userPasswordAttribute;
   }
   
   public void setUserPasswordAttribute(String userPasswordAttribute)
   {
      this.userPasswordAttribute = userPasswordAttribute;
   }
   
   public String getFirstNameAttribute()
   {
      return firstNameAttribute;
   }
   
   public void setFirstNameAttribute(String firstNameAttribute)
   {
      this.firstNameAttribute = firstNameAttribute;
   }
   
   public String getLastNameAttribute()
   {
      return lastNameAttribute;
   }
   
   public void setLastNameAttribute(String lastNameAttribute)
   {
      this.lastNameAttribute = lastNameAttribute;
   }
   
   public String getFullNameAttribute()
   {
      return fullNameAttribute;
   }
   
   public void setFullNameAttribute(String fullNameAttribute)
   {
      this.fullNameAttribute = fullNameAttribute;
   }
   
   public String getEnabledAttribute()
   {
      return enabledAttribute;
   }
   
   public void setEnabledAttribute(String enabledAttribute)
   {
      this.enabledAttribute = enabledAttribute;
   }
   
   public String getObjectClassAttribute()
   {
      return objectClassAttribute;
   }
   
   public void setObjectClassAttribute(String objectClassAttribute)
   {
      this.objectClassAttribute = objectClassAttribute;
   }
   
   public String[] getRoleObjectClasses()
   {
      return roleObjectClasses;
   }
   
   public void setRoleObjectClass(String[] roleObjectClasses)
   {
      this.roleObjectClasses = roleObjectClasses;
   }
   
   public String[] getUserObjectClasses()
   {
      return userObjectClasses;
   }
   
   public void setUserObjectClasses(String[] userObjectClasses)
   {
      this.userObjectClasses = userObjectClasses;
   }
   
   public int getSearchTimeLimit()
   {
      return searchTimeLimit;
   }
   
   public void setSearchTimeLimit(int searchTimeLimit)
   {
      this.searchTimeLimit = searchTimeLimit;
   }
   
   public String getSearchScope()
   {
      switch (searchScope)
      {
         case SearchControls.OBJECT_SCOPE: return "OBJECT_SCOPE";
         case SearchControls.ONELEVEL_SCOPE : return "ONELEVEL_SCOPE";
         case SearchControls.SUBTREE_SCOPE : return "SUBTREE_SCOPE";
         default: return "UNKNOWN";
      }
   }
   
   public void setSearchScope(String value)
   {
      if ("OBJECT_SCOPE".equals(value))
      {
         searchScope = SearchControls.OBJECT_SCOPE;
      }
      else if ("ONELEVEL_SCOPE".equals(value))
      {
         searchScope = SearchControls.ONELEVEL_SCOPE;
      }
      else
      {
         searchScope = SearchControls.SUBTREE_SCOPE;
         if (!"SUBTREE_SCOPE".equals(value))
         {
            log.warn("Invalid search scope specified (" + value + ") - search scope set to SUBTREE_SCOPE");
         }
      }
   }
   
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
   
   protected InitialLdapContext initialiseContext()
      throws NamingException
   {
      return initialiseContext(getBindDN(), getBindCredentials());
   }
   
   protected InitialLdapContext initialiseContext(String principal, String credentials)
      throws NamingException
   {
      Properties env = new Properties();

      env.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
      
      String providerUrl = String.format("ldap://%s:%d", getServerAddress(), getServerPort());
      env.setProperty(Context.PROVIDER_URL, providerUrl);
      
      env.setProperty(Context.SECURITY_PRINCIPAL, principal);
      env.setProperty(Context.SECURITY_CREDENTIALS, credentials);
      
      InitialLdapContext ctx = new InitialLdapContext(env, null);
      return ctx;
   }
   
   protected String getUserDN(String username)
   {
      return String.format("%s%s%s", getUserDNPrefix(), username, getUserDNSuffix());
   }
   
   protected String getRoleDN(String role)
   {
      return String.format("%s%s%s", getRoleDNPrefix(), role, getRoleDNSuffix());
   }
      
   public boolean authenticate(String username, String password)
   {
      final String securityPrincipal = getUserDN(username);
      
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext(securityPrincipal, password);
         
         if (getEnabledAttribute() != null)
         {
            Attributes attribs = ctx.getAttributes(securityPrincipal, new String[] { getEnabledAttribute() });
            Attribute enabledAttrib = attribs.get( getEnabledAttribute() );
            if (enabledAttrib != null)
            {
               for (int r = 0; r < enabledAttrib.size(); r++)
               {
                  Object value = enabledAttrib.get(r);
                  if (LDAP_BOOLEAN_TRUE.equals(value)) return true;
               }
            }
            return false;
         }
                           
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Authentication error", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean changePassword(String name, String password)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         BasicAttribute passwordAttrib = new BasicAttribute(getUserPasswordAttribute(), password);
         ModificationItem mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, passwordAttrib);
         ctx.modifyAttributes(getUserDN(name), new ModificationItem[] { mod });
         
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to change password", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean createRole(String role)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         Attributes roleAttribs = new BasicAttributes();
         
         BasicAttribute roleClass = new BasicAttribute(getObjectClassAttribute());
         for (String objectClass : getRoleObjectClasses())
         {
            roleClass.add(objectClass);
         }
         
         roleAttribs.put(roleClass);
         roleAttribs.put(new BasicAttribute(getRoleNameAttribute(), role));
         
         String roleDN = getRoleDN(role);
         ctx.createSubcontext(roleDN, roleAttribs);
         
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to create role", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }
   
   public boolean createUser(String username, String password, String firstname, String lastname)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         Attributes userAttribs = new BasicAttributes();
         
         BasicAttribute userClass = new BasicAttribute(getObjectClassAttribute());
         for (String objectClass : getUserObjectClasses())
         {
            userClass.add(objectClass);
         }
         
         userAttribs.put(userClass);
         userAttribs.put(new BasicAttribute(getUserNameAttribute(), username));
         userAttribs.put(new BasicAttribute(getUserPasswordAttribute(), password));
         
         if (getFirstNameAttribute() != null && firstname != null)
         {
            userAttribs.put(new BasicAttribute(getFirstNameAttribute(), firstname));
         }
         
         if (getLastNameAttribute() != null && lastname != null)
         {
            userAttribs.put(new BasicAttribute(getLastNameAttribute(), lastname));
         }
         
         if (getFullNameAttribute() != null && firstname != null && lastname != null)
         {
            userAttribs.put(new BasicAttribute(getFullNameAttribute(), firstname + " " + lastname));
         }
         
         if (getEnabledAttribute() != null)
         {
            userAttribs.put(new BasicAttribute(getEnabledAttribute(), LDAP_BOOLEAN_TRUE));
         }
         
         String userDN = String.format("%s=%s,%s", getUserNameAttribute(), username, getUserContextDN() );
         ctx.createSubcontext(userDN, userAttribs);
         
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to create user", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean createUser(String username, String password)
   {
      return createUser(username, password, null, null);
   }

   public boolean deleteRole(String role)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
                 
         // Delete the role entry itself
         String roleDN = String.format("%s=%s,%s", getRoleNameAttribute(), role, getRoleContextDN() );
         ctx.destroySubcontext(roleDN);
         
         // Then delete all user attributes that point to this role
         int searchScope = SearchControls.SUBTREE_SCOPE;
         int searchTimeLimit = 10000;
         
         String[] roleAttr = { getUserRoleAttribute() };
                           
         SearchControls controls = new SearchControls();
         controls.setSearchScope(searchScope);
         controls.setReturningAttributes(roleAttr);
         controls.setTimeLimit(searchTimeLimit);
         
         StringBuilder roleFilter = new StringBuilder();
         Object[] filterArgs = new Object[getUserObjectClasses().length + 1];
         filterArgs[0] = roleDN;
         
         roleFilter.append("(&(");
         roleFilter.append(getUserRoleAttribute());
         roleFilter.append("={0})");
         
         for (int i = 0; i < getUserObjectClasses().length; i++)
         {
            roleFilter.append("(");
            roleFilter.append(getObjectClassAttribute());
            roleFilter.append("={");
            roleFilter.append(i + 1);
            roleFilter.append("})");
            filterArgs[i + 1] = getUserObjectClasses()[i];
         }
         
         roleFilter.append(")");
                  
         NamingEnumeration<?> answer = ctx.search(getUserContextDN(), roleFilter.toString(), filterArgs, controls);
         while (answer.hasMore())
         {
            SearchResult sr = (SearchResult) answer.next();
            Attributes attrs = sr.getAttributes();
            Attribute user = attrs.get( getUserRoleAttribute() );
            user.remove(roleDN);
            ctx.modifyAttributes(sr.getNameInNamespace(), new ModificationItem[] {
               new ModificationItem(DirContext.REPLACE_ATTRIBUTE, user)});
         }
         answer.close();
         
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to delete role", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }
   
   public boolean roleExists(String role)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         int searchScope = SearchControls.SUBTREE_SCOPE;
         int searchTimeLimit = 10000;
         
         String[] roleAttr = { getRoleNameAttribute() };
                           
         SearchControls controls = new SearchControls();
         controls.setSearchScope(searchScope);
         controls.setReturningAttributes(roleAttr);
         controls.setTimeLimit(searchTimeLimit);
         
         String roleFilter = "(&(" + getObjectClassAttribute() + "={0})(" + getRoleNameAttribute() + "={1}))";
         Object[] filterArgs = { getRoleObjectClasses(), role};
         
         NamingEnumeration<?> answer = ctx.search(getRoleContextDN(), roleFilter, filterArgs, controls);
         while (answer.hasMore())
         {
            SearchResult sr = (SearchResult) answer.next();
            Attributes attrs = sr.getAttributes();
            Attribute user = attrs.get( getRoleNameAttribute() );
            
            for (int i = 0; i < user.size(); i++)
            {
               Object value = user.get(i);
               if (role.equals(value)) return true;
            }
         }
         answer.close();

         return false;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Error getting roles", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean deleteUser(String name)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
                 
         String userDN = getUserDN(name);
         ctx.destroySubcontext(userDN);
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to delete user", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }
   
   public boolean isUserEnabled(String name)
   {
      if (getEnabledAttribute() == null) return true;

      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         String userDN = getUserDN(name);
         Attributes attribs = ctx.getAttributes(userDN, new String[] { getEnabledAttribute() });
         Attribute enabledAttrib = attribs.get( getEnabledAttribute() );
         if (enabledAttrib != null)
         {
            for (int r = 0; r < enabledAttrib.size(); r++)
            {
               Object value = enabledAttrib.get(r);
               if (LDAP_BOOLEAN_TRUE.equals(value)) return true;
            }
         }

         return false;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to delete user", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean disableUser(String name)
   {
      if (getEnabledAttribute() == null) return false;
      
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         String userDN = getUserDN(name);
         BasicAttribute enabledAttrib = new BasicAttribute(getEnabledAttribute(), LDAP_BOOLEAN_FALSE);
         ModificationItem mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, enabledAttrib);
         
         ctx.modifyAttributes(userDN, new ModificationItem[] { mod });
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to disable user", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean enableUser(String name)
   {
      if (getEnabledAttribute() == null) return false;
      
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         String userDN = getUserDN(name);
         BasicAttribute enabledAttrib = new BasicAttribute(getEnabledAttribute(), LDAP_BOOLEAN_TRUE);
         ModificationItem mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, enabledAttrib);
         
         ctx.modifyAttributes(userDN, new ModificationItem[] { mod });
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to disable user", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public List<String> getGrantedRoles(String name)
   {
      Set<String> userRoles = new HashSet<String>();
      
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
                  
         String userFilter = "(" + getUserNameAttribute() + "={0})";
         String[] roleAttr = { getUserRoleAttribute() };
                  
         SearchControls controls = new SearchControls();
         controls.setSearchScope(searchScope);
         controls.setReturningAttributes(roleAttr);
         controls.setTimeLimit(getSearchTimeLimit());
         Object[] filterArgs = {name};
         
         NamingEnumeration<?> answer = ctx.search(getUserContextDN(), userFilter, filterArgs, controls);
         while (answer.hasMore())
         {
            SearchResult sr = (SearchResult) answer.next();
            Attributes attrs = sr.getAttributes();
            Attribute roles = attrs.get( getUserRoleAttribute() );
            if (roles != null)
            {
               for (int r = 0; r < roles.size(); r++)
               {
                  Object value = roles.get(r);
                  String roleName = null;
                  if (getRoleAttributeIsDN() == true)
                  {
                     String roleDN = value.toString();
                     String[] returnAttribute = {getRoleNameAttribute()};
                     try
                     {
                        Attributes result2 = ctx.getAttributes(roleDN, returnAttribute);
                        Attribute roles2 = result2.get(getRoleNameAttribute());
                        if( roles2 != null )
                        {
                           for(int m = 0; m < roles2.size(); m ++)
                           {
                              roleName = (String) roles2.get(m);
                              userRoles.add(roleName);
                           }
                        }
                     }
                     catch (NamingException ex)
                     {
                        throw new IdentityManagementException("Failed to query roles", ex);
                     }
                  }
                  else
                  {
                     // The role attribute value is the role name
                     roleName = value.toString();
                     userRoles.add(roleName);
                  }
               }
            }
         }
         answer.close();
         
         return new ArrayList<String>(userRoles);
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Error getting roles", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public List<String> getImpliedRoles(String name)
   {
      return getGrantedRoles(name);
   }

   public boolean grantRole(String name, String role)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         String userDN = getUserDN(name);
                  
         BasicAttribute roleAttrib = new BasicAttribute(getUserRoleAttribute(),
               getRoleAttributeIsDN() ? getRoleDN(role) : role);
         ModificationItem mod = new ModificationItem(DirContext.ADD_ATTRIBUTE, roleAttrib);
         
         ctx.modifyAttributes(userDN, new ModificationItem[] { mod });
         return true;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to grant role", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }
   
   public boolean revokeRole(String name, String role)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         String userDN = getUserDN(name);
         
         Attributes roleAttribs = ctx.getAttributes(userDN, new String[] { getUserRoleAttribute() });
         Attribute roleAttrib = roleAttribs.get( getUserRoleAttribute() );
         if (roleAttrib != null)
         {
            boolean modified = false;
            for (int i = roleAttrib.size() - 1; i >= 0; i--)
            {
               if (getRoleAttributeIsDN())
               {
                  Attributes attribs = ctx.getAttributes((String) roleAttrib.get(i),
                        new String[] { getRoleNameAttribute() });
                  Attribute roleNameAttrib = attribs.get( getRoleNameAttribute() );
                  for (int j = 0; j < roleNameAttrib.size(); j++)
                  {
                     if (role.equals(roleNameAttrib.get(j)))
                     {
                        modified = true;
                        roleAttrib.remove(i);
                     }
                  }
               }
               else if (role.equals(roleAttrib.get(i)))
               {
                  modified = true;
                  roleAttrib.remove(i);
               }
            }
            
            if (modified)
            {
               ModificationItem mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, roleAttrib);
               ctx.modifyAttributes(userDN, new ModificationItem[] { mod });
            }
         }
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Failed to grant role", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
      
      return false;
   }

   public List<String> listRoles()
   {
      List<String> roles = new ArrayList<String>();
      
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
         
         String[] roleAttr = { getRoleNameAttribute() };
                           
         SearchControls controls = new SearchControls();
         controls.setSearchScope(searchScope);
         controls.setReturningAttributes(roleAttr);
         controls.setTimeLimit(getSearchTimeLimit());
         
         StringBuilder roleFilter = new StringBuilder();
         
         Object[] filterArgs = new Object[getRoleObjectClasses().length];
         for (int i = 0; i < getRoleObjectClasses().length; i++)
         {
            roleFilter.append("(");
            roleFilter.append(getObjectClassAttribute());
            roleFilter.append("={");
            roleFilter.append(i);
            roleFilter.append("})");
            filterArgs[i] = getRoleObjectClasses()[i];
         }
         
         NamingEnumeration<?> answer = ctx.search( getRoleContextDN(), roleFilter.toString(),
               filterArgs, controls);
         while (answer.hasMore())
         {
            SearchResult sr = (SearchResult) answer.next();
            Attributes attrs = sr.getAttributes();
            Attribute user = attrs.get( getRoleNameAttribute() );
            
            for (int i = 0; i < user.size(); i++)
            {
               Object value = user.get(i);
               roles.add(value.toString());
            }
         }
         answer.close();
         return roles;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Error getting roles", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }
   

   public List<String> listGrantableRoles()
   {
      return listRoles();
   }

   public List<String> listUsers()
   {
      return listUsers(null);
   }

   public List<String> listUsers(String filter)
   {
      List<String> users = new ArrayList<String>();
      
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
       
         String[] userAttr = {getUserNameAttribute()};
                           
         SearchControls controls = new SearchControls();
         controls.setSearchScope(searchScope);
         controls.setReturningAttributes(userAttr);
         controls.setTimeLimit(getSearchTimeLimit());
                  
         StringBuilder userFilter = new StringBuilder("(&");
         
         Object[] filterArgs = new Object[getUserObjectClasses().length];
         for (int i = 0; i < getUserObjectClasses().length; i++)
         {
            userFilter.append("(");
            userFilter.append(getObjectClassAttribute());
            userFilter.append("={");
            userFilter.append(i);
            userFilter.append("})");
            filterArgs[i] = getUserObjectClasses()[i];
         }
         
         userFilter.append(")");
         
         NamingEnumeration<?> answer = ctx.search(getUserContextDN(), userFilter.toString(), filterArgs, controls);
         while (answer.hasMore())
         {
            SearchResult sr = (SearchResult) answer.next();
            Attributes attrs = sr.getAttributes();
            Attribute user = attrs.get(getUserNameAttribute());
            
            for (int i = 0; i < user.size(); i++)
            {
               Object value = user.get(i);
               
               if (filter != null)
               {
                  if (value.toString().toLowerCase().contains(filter.toLowerCase()))
                  {
                     users.add(value.toString());
                  }
               }
               else
               {
                  users.add(value.toString());
               }
            }
         }
         answer.close();
         return users;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Error getting users", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public boolean userExists(String name)
   {
      InitialLdapContext ctx = null;
      try
      {
         ctx = initialiseContext();
       
         String[] userAttr = {getUserNameAttribute()};
                           
         SearchControls controls = new SearchControls();
         controls.setSearchScope(searchScope);
         controls.setReturningAttributes(userAttr);
         controls.setTimeLimit(getSearchTimeLimit());
                  
         StringBuilder userFilter = new StringBuilder();
         
         Object[] filterArgs = new Object[getUserObjectClasses().length];
         for (int i = 0; i < getUserObjectClasses().length; i++)
         {
            userFilter.append("(");
            userFilter.append(getObjectClassAttribute());
            userFilter.append("={");
            userFilter.append(i);
            userFilter.append("})");
            filterArgs[i] = getUserObjectClasses()[i];
         }
         
         NamingEnumeration<?> answer = ctx.search(getUserContextDN(), userFilter.toString(), filterArgs, controls);
         while (answer.hasMore())
         {
            SearchResult sr = (SearchResult) answer.next();
            Attributes attrs = sr.getAttributes();
            Attribute user = attrs.get(getUserNameAttribute());
            
            for (int i = 0; i < user.size(); i++)
            {
               Object value = user.get(i);
               if (name.equals(value))
               {
                  answer.close();
                  return true;
               }
            }
         }
         answer.close();
         return false;
      }
      catch (NamingException ex)
      {
         throw new IdentityManagementException("Error getting users", ex);
      }
      finally
      {
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException ex) {}
         }
      }
   }

   public List<String> getRoleGroups(String name)
   {
      // TODO Auto-generated method stub
      return null;
   }
   
   public List<Principal> listMembers(String role)
   {
      // TODO implement
      return null;
   }

   public boolean addRoleToGroup(String role, String group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean removeRoleFromGroup(String role, String group)
   {
      // TODO Auto-generated method stub
      return false;
   }
}
