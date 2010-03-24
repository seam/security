package org.jboss.seam.security.management;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

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
import org.jboss.seam.security.util.AnnotatedBeanProperty;
import org.jboss.seam.security.util.TypedBeanProperty;

/**
 * The configuration for JpaIdentityStore
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class JpaIdentityStoreConfig
{
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
      
   //@Current // FIXME temporarily disable!!
   IdentityStoreEntityClasses entityClasses;
   
   @Inject
   public void initProperties()
   {
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
      
   public Class<?> getUserEntityClass()
   {
      if (userEntityClass == null)
      {
         userEntityClass = entityClasses.getUserEntityClass();
      }
      
      return userEntityClass;
   }
   
   public void setUserEntityClass(Class<?> userEntityClass)
   {
      this.userEntityClass = userEntityClass;
   }
   
   public Class<?> getRoleEntityClass()
   {
      if (roleEntityClass == null)
      {
         roleEntityClass = entityClasses.getRoleEntityClass();
      }
      
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
