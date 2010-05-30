package org.jboss.seam.security.management;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.persistence.EntityManager;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;
import org.jboss.weld.extensions.util.AnnotatedBeanProperty;
import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentityType;
import org.picketlink.idm.api.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IdentityStore implementation that allows identity related data to be 
 * persisted in a database via JPA
 *  
 * @author Shane Bryzak
 */
public @ApplicationScoped class JpaIdentityStore implements IdentityStore, Serializable
{
   private static final long serialVersionUID = 7729139146633529501L;
   
   private static final String DEFAULT_USER_IDENTITY_TYPE = "USER";
   private static final String DEFAULT_ROLE_IDENTITY_TYPE = "ROLE";
   private static final String DEFAULT_GROUP_IDENTITY_TYPE = "GROUP";   
   
   private static final String DEFAULT_RELATIONSHIP_TYPE_MEMBERSHIP = "MEMBERSHIP";
   private static final String DEFAULT_RELATIONSHIP_TYPE_ROLE = "ROLE";
      
   private Logger log = LoggerFactory.getLogger(JpaIdentityStore.class);
   
   // The following entity classes are configurable
   private Class<?> identityObjectEntity;
   private Class<?> relationshipEntity;
   private Class<?> credentialEntity;
   private Class<?> attributeEntity;
   private Class<?> roleTypeEntity;
   
   // The following entity classes may be determined automatically
   private Class<?> identityTypeEntity;
   private Class<?> relationshipTypeEntity;
   private Class<?> credentialTypeEntity;
   
   
   private AnnotatedBeanProperty<IdentityProperty> identityNameProperty;
   private AnnotatedBeanProperty<IdentityProperty> identityTypeProperty;
   private AnnotatedBeanProperty<IdentityProperty> identityTypeNameProperty;
   private AnnotatedBeanProperty<IdentityProperty> relationshipNameProperty;
   private AnnotatedBeanProperty<IdentityProperty> relationshipTypeProperty;
   private AnnotatedBeanProperty<IdentityProperty> relationshipFromProperty;
   private AnnotatedBeanProperty<IdentityProperty> relationshipToProperty;
   private AnnotatedBeanProperty<IdentityProperty> relationshipTypeNameProperty;
   private AnnotatedBeanProperty<IdentityProperty> credentialTypeProperty;
   private AnnotatedBeanProperty<IdentityProperty> credentialValueProperty;
   private AnnotatedBeanProperty<IdentityProperty> credentialTypeNameProperty;
   private AnnotatedBeanProperty<IdentityProperty> attributeNameProperty;
   private AnnotatedBeanProperty<IdentityProperty> attributeValueProperty;
   private AnnotatedBeanProperty<IdentityProperty> roleTypeNameProperty;
   
   private String userIdentityType = DEFAULT_USER_IDENTITY_TYPE;
   private String roleIdentityType = DEFAULT_ROLE_IDENTITY_TYPE;
   private String groupIdentityType = DEFAULT_GROUP_IDENTITY_TYPE;
   
   private String relationshipTypeMembership = DEFAULT_RELATIONSHIP_TYPE_MEMBERSHIP;
   private String relationshipTypeRole = DEFAULT_RELATIONSHIP_TYPE_ROLE;
   
   private class EntityProperty extends AnnotatedBeanProperty<IdentityProperty> 
   {
      private PropertyType pt;      
      
      public EntityProperty(Class<?> cls, Class<IdentityProperty> annotationClass, PropertyType pt)
      {
         super(cls, annotationClass);
         this.pt = pt;                 
      }
   
      public boolean isMatch(IdentityProperty p)
      {
         return p.value().equals(pt);  
      }           
   }
   
   @Inject
   public void init()
   {
      if (identityObjectEntity == null)
      {
         throw new IdentityManagementException(
               "Error initializing JpaIdentityStore - identityObjectEntity not set");
      }
      
      if (relationshipEntity == null)
      {
         throw new IdentityManagementException(
               "Error initializing JpaIdentityStore - identityObjectRelationshipEntity not set");
      }
      
      identityNameProperty = new EntityProperty(identityObjectEntity, 
            IdentityProperty.class, PropertyType.NAME);
      
      identityTypeProperty = new EntityProperty(identityObjectEntity, 
            IdentityProperty.class, PropertyType.TYPE);
      
      if (!String.class.equals(identityTypeProperty.getPropertyType()))
      {
         // If the identity type property isn't a String, it must be a related entity
         identityTypeEntity = (Class<?>) identityTypeProperty.getPropertyType();
         
         identityTypeNameProperty = new EntityProperty(identityTypeEntity, 
               IdentityProperty.class, PropertyType.NAME);
      }
      
      relationshipNameProperty = new EntityProperty(relationshipEntity, 
            IdentityProperty.class, PropertyType.NAME);
      
      relationshipFromProperty = new EntityProperty(relationshipEntity, 
            IdentityProperty.class, PropertyType.RELATIONSHIP_FROM);
      
      relationshipToProperty = new EntityProperty(relationshipEntity, 
            IdentityProperty.class, PropertyType.RELATIONSHIP_TO);
      
      relationshipTypeProperty = new EntityProperty(relationshipEntity, 
            IdentityProperty.class, PropertyType.TYPE);
      
      if (!String.class.equals(relationshipTypeProperty.getPropertyType()))
      {
         relationshipTypeEntity = (Class<?>) relationshipTypeProperty.getPropertyType(); 
         relationshipTypeNameProperty = new EntityProperty(relationshipTypeEntity, 
               IdentityProperty.class, PropertyType.NAME);
      }
      
      // If a credential entity has been configured, scan it
      if (credentialEntity != null)
      {
         credentialTypeProperty = new EntityProperty(credentialEntity, 
               IdentityProperty.class, PropertyType.TYPE);
         
         if (!String.class.equals(credentialTypeProperty.getPropertyType()))
         {
            credentialTypeEntity = (Class<?>) credentialTypeProperty.getPropertyType();
            credentialTypeNameProperty = new EntityProperty(credentialTypeEntity, 
                  IdentityProperty.class, PropertyType.NAME);
         }
         
         credentialValueProperty = new EntityProperty(credentialEntity, 
               IdentityProperty.class, PropertyType.VALUE);
      }
      // otherwise assume that the credential value is stored in the identityObjectEntity
      else
      {
         // TODO implement this, we'll probably need some new PropertyType enums to support it
      }
      
      
      
   }
   
   public Class<?> getIdentityObjectEntity()
   {
      return identityObjectEntity;
   }
   
   public void setIdentityObjectEntity(Class<?> identityObjectEntity)
   {
      this.identityObjectEntity = identityObjectEntity;
   }
   
   public Class<?> getIdentityObjectRelationshipEntity()
   {
      return relationshipEntity;
   }
   
   public void setIdentityObjectRelationshipEntity(Class<?> identityObjectRelationshipEntity)
   {
      this.relationshipEntity = identityObjectRelationshipEntity;
   }
   
   public Class<?> getIdentityObjectCredentialEntity()
   {
      return credentialEntity;
   }
   
   public void setIdentityObjectCredentialEntity(Class<?> identityObjectCredentialEntity)
   {
      this.credentialEntity = identityObjectCredentialEntity;
   }
   
   public Class<?> getIdentityObjectAttributeEntity()
   {
      return attributeEntity;
   }
   
   public void setIdentityObjectAttributeEntity(Class<?> identityObjectAttributeEntity)
   {
      this.attributeEntity = identityObjectAttributeEntity;
   }
   
   public Class<?> getIdentityRoleTypeEntity()
   {
      return roleTypeEntity;
   }
   
   public void setIdentityRoleTypeEntity(Class<?> identityRoleTypeEntity)
   {
      this.roleTypeEntity = identityRoleTypeEntity;
   }
   
   public String getUserIdentityType()
   {
      return userIdentityType;
   }
   
   public void setUserIdentityType(String userIdentityType)
   {
      this.userIdentityType = userIdentityType;
   }
   
   public String getRoleIdentityType()
   {
      return roleIdentityType;
   }
   
   public void setRoleIdentityType(String roleIdentityType)
   {
      this.roleIdentityType = roleIdentityType;
   }
   
   public String getGroupIdentityType()
   {
      return groupIdentityType;
   }
   
   public void setGroupIdentityType(String groupIdentityType)
   {
      this.groupIdentityType = groupIdentityType;
   }
   
   public String getRelationshipTypeMembership()
   {
      return relationshipTypeMembership;
   }
   
   public void setRelationshipTypeMembership(String relationshipTypeMembership)
   {
      this.relationshipTypeMembership = relationshipTypeMembership;
   }
   
   public String getRelationshipTypeRole()
   {
      return relationshipTypeRole;
   }
   
   public void setRelationshipTypeRole(String relationshipTypeRole)
   {
      this.relationshipTypeRole = relationshipTypeRole;
   }

   /**
    * 
    */
   @Inject Instance<EntityManager> entityManagerInstance;
   
   /**
    * 
    */
   @Inject PasswordEncoder passwordEncoder;   


   public boolean addUserToGroup(String username, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean authenticate(String username, Credential credential)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean updateCredential(String username, Credential credential)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createGroup(String name, String groupType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createRoleType(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean createUser(String username, Credential credential, Map<String,?> attributes)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteGroup(String name, String groupType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteRoleType(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean deleteUser(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean disableUser(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean enableUser(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public Group findGroup(String name, String groupType)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> findUsers()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> findUsers(String filter)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean grantRole(String username, String roleType, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean isUserEnabled(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public List<String> listGrantableRoleTypes()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<Role> listGrantedRoles(String username)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<IdentityType> listGroupMembers(Group group)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<Role> listImpliedRoles(String username)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<IdentityType> listRoleMembers(String roleType, Group group)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> listRoleTypes()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean removeUserFromGroup(String username, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean revokeRole(String username, String roleType, Group group)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean roleTypeExists(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean supportsFeature(Feature feature)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean userExists(String username)
   {
      // TODO Auto-generated method stub
      return false;
   }
}
