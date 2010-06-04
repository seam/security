package org.jboss.seam.security.management;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;
import org.jboss.weld.extensions.util.properties.Property;
import org.jboss.weld.extensions.util.properties.query.NamedPropertyCriteria;
import org.jboss.weld.extensions.util.properties.query.PropertyCriteria;
import org.jboss.weld.extensions.util.properties.query.PropertyQueries;
import org.jboss.weld.extensions.util.properties.query.TypedPropertyCriteria;
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
   
   private Logger log = LoggerFactory.getLogger(JpaIdentityStore.class);   
   
   private static final String DEFAULT_USER_IDENTITY_TYPE = "USER";
   private static final String DEFAULT_ROLE_IDENTITY_TYPE = "ROLE";
   private static final String DEFAULT_GROUP_IDENTITY_TYPE = "GROUP";   
   
   private static final String DEFAULT_RELATIONSHIP_TYPE_MEMBERSHIP = "MEMBERSHIP";
   private static final String DEFAULT_RELATIONSHIP_TYPE_ROLE = "ROLE";
   
   private static final String DEFAULT_ATTRIBUTE_USER_ENABLED = "ENABLED";
   private static final String DEFAULT_ATTRIBUTE_PASSWORD_SALT = "PASSWORD_SALT";

   // Property keys
   
   private static final String PROPERTY_IDENTITY_NAME = "IDENTITY_NAME";
   private static final String PROPERTY_IDENTITY_TYPE = "IDENTITY_TYPE";
   private static final String PROPERTY_IDENTITY_TYPE_NAME = "IDENTITY_TYPE_NAME";
      
   // Entity classes
   
   private Class<?> identityClass;
   private Class<?> relationshipClass;
   private Class<?> relationshipTypeClass;
   private Class<?> credentialClass;
   private Class<?> credentialTypeClass;
   private Class<?> attributeClass;
   private Class<?> roleTypeClass;
   
   private String userIdentityType = DEFAULT_USER_IDENTITY_TYPE;
   private String roleIdentityType = DEFAULT_ROLE_IDENTITY_TYPE;
   private String groupIdentityType = DEFAULT_GROUP_IDENTITY_TYPE;
   
   private String relationshipTypeMembership = DEFAULT_RELATIONSHIP_TYPE_MEMBERSHIP;
   private String relationshipTypeRole = DEFAULT_RELATIONSHIP_TYPE_ROLE;
   
   /**
    * Model properties
    */
   private Map<String,Property<?>> modelProperties = new HashMap<String,Property<?>>();   
   
   private class PropertyTypeCriteria implements PropertyCriteria
   {
      private PropertyType pt;
      
      public PropertyTypeCriteria(PropertyType pt)
      {
         this.pt = pt;
      }
      
      public boolean fieldMatches(Field f)
      {
         return f.isAnnotationPresent(IdentityProperty.class) &&
            f.getAnnotation(IdentityProperty.class).value().equals(pt);
      }

      public boolean methodMatches(Method m)
      {
         return m.isAnnotationPresent(IdentityProperty.class) &&
            m.getAnnotation(IdentityProperty.class).value().equals(pt);
      }
      
   }
      
   @Inject
   public void init()
   {
      configureIdentityName();
      configureIdentityType();
      
      //configureCredentials();
      //configureRelationships();
      //configureAttributes();
      
      //roleTypeNameProperty = new EntityProperty(roleTypeEntity, PropertyType.NAME);
   }
   
   protected void configureIdentityName()
   {      
      if (identityClass == null)
      {
         throw new IdentityManagementException(
               "Error initializing JpaIdentityStore - identityClass not set");
      }
      
      List<Property<String>> props = PropertyQueries.<String>createQuery(identityClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous identity name property in identity class " + identityClass.getName());
      }
      else
      {
         // No name property explicitly configured, let's query by property name
         String[] possibleNames = new String[] { "username", "userName", "name" };
         props = PropertyQueries.<String>createQuery(identityClass)
            .addCriteria(new NamedPropertyCriteria(possibleNames))
            .getResultList();
         
         if (props.size() == 1)
         {
            // Bingo, use the name property
            modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
         }
         else if (props.size() > 1)
         {
            // multiple "name" properties found
            search: for (String name : possibleNames)
            {
               for (Property<String> p : props)
               {
                  if (name.equals(p.getName()))
                  {
                     modelProperties.put(PROPERTY_IDENTITY_NAME, p);
                     break search;
                  }
               }
            }
         }
         else if (props.isEmpty())
         {
            // Last resort - check whether the entity class exposes a single String property
            // if so, let's assume it's the identity name
            props = PropertyQueries.<String>createQuery(identityClass)
               .addCriteria(new TypedPropertyCriteria(String.class))
               .getResultList();
            if (props.size() == 1)
            {
               modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
            }
         }
      }

      if (!modelProperties.containsKey(PROPERTY_IDENTITY_NAME))
      {
         throw new IdentityManagementException("Error initializing JpaIdentityStore - no valid identity name property found.");
      }
   }
   
   protected void configureIdentityType()
   {      
      List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous identity type property in identity class " + identityClass.getName());
      }
      else
      {
         // No type property explicitly configured, query by property name
         String[] possibleNames = new String[] { "identityObjectType", 
               "identityType", "identityObjectTypeName", "identityTypeName", 
               "typeName", "discriminator", "accountType", "userType", "type" };
         props = PropertyQueries.createQuery(identityClass)
            .addCriteria(new NamedPropertyCriteria(possibleNames))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
         }
         else if (props.size() > 1)
         {
            search: for (String name : possibleNames)
            {
               for (Property<Object> p : props)
               {
                  if (name.equals(p.getName()))
                  {
                     modelProperties.put(PROPERTY_IDENTITY_TYPE, p);
                     break search;
                  }
               }
            }
            
         }
         else if (props.isEmpty())
         {
            // Last resort - let's check all properties, and try to find one
            // with an entity type that has "type" in its name
            props = PropertyQueries.createQuery(identityClass).getResultList();
            search: for (Property<Object> typeProp : props)
            {
               if (typeProp.getJavaClass().isAnnotationPresent(Entity.class) && 
                     (typeProp.getJavaClass().getSimpleName().contains("type") ||
                           typeProp.getJavaClass().getSimpleName().contains("Type")))
               {
                  // we have a potential match, let's check if this entity has a name property
                  Property<String> nameProp = findIdentityTypeNameProperty(typeProp.getJavaClass());
                  if (nameProp != null)
                  {
                     modelProperties.put(PROPERTY_IDENTITY_TYPE, typeProp);
                     modelProperties.put(PROPERTY_IDENTITY_TYPE_NAME, nameProp);
                     break search;
                  }
               }
            }
         }         
      }      
      
      Property<?> typeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);
      
      if (typeProp == null)
      {
         throw new IdentityManagementException("Error initializing JpaIdentityStore - no valid identity type property found.");
      }
      
      if (!String.class.equals(typeProp.getJavaClass()) && 
            !modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME))
      {
         // We're not dealing with a simple type name - validate the lookup type
         Property<String> nameProp = findIdentityTypeNameProperty(typeProp.getJavaClass());
         if (nameProp != null)
         {
            modelProperties.put(PROPERTY_IDENTITY_TYPE_NAME, nameProp);
         }
         else
         {
            throw new IdentityManagementException("Error initializing JpaIdentityStore - no valid identity type name property found.");
         }
      }
   }
   
   protected Property<String> findIdentityTypeNameProperty(Class<?> identityTypeClass)
   {
      List<Property<String>> props = PropertyQueries.<String>createQuery(identityTypeClass)
         .addCriteria(new TypedPropertyCriteria(String.class))
         .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
         .getResultList();
      
      if (props.size() == 1)
      {
         return props.get(0);
      }
      else
      {
         String[] possibleNames = new String[] { "identityObjectTypeName", "identityTypeName", "typeName", "name" };
         props = PropertyQueries.<String>createQuery(identityTypeClass)
            .addCriteria(new TypedPropertyCriteria(String.class))
            .addCriteria(new NamedPropertyCriteria(possibleNames))
            .getResultList();
         
         for (String name : possibleNames)
         {
            for (Property<String> prop : props)
            {
               if (name.equals(prop.getName())) return prop;
            }
         }
      }      
      
      return null;
   }
   
   protected void configureCredentials()
   {
      // If a credential entity has been configured, scan it
      if (credentialEntity != null)
      {
         credentialTypeProperty = new EntityProperty(credentialEntity, PropertyType.TYPE);
         
         // If the credential type property isn't a string, assume the credential type
         // is in another table
         if (!String.class.equals(credentialTypeProperty.getPropertyType()))
         {
            credentialTypeEntity = (Class<?>) credentialTypeProperty.getPropertyType();
            credentialTypeNameProperty = new EntityProperty(credentialTypeEntity, PropertyType.NAME);
            
            credentialIdentityProperty = new TypedBeanProperty(credentialTypeEntity, identityObjectEntity);
         }
         
         credentialValueProperty = new EntityProperty(credentialEntity, PropertyType.VALUE);
         
         
      }
      else
      {
         // otherwise assume that the credential value is stored in the identityObjectEntity         
         credentialTypeProperty = new EntityProperty(identityObjectEntity, PropertyType.CREDENTIAL_TYPE);
         credentialValueProperty = new EntityProperty(identityObjectEntity, PropertyType.CREDENTIAL);
      }
      
      
   }
   
   protected void configureRelationships()
   {
      if (relationshipEntity == null)
      {
         throw new IdentityManagementException(
               "Error initializing JpaIdentityStore - identityObjectRelationshipEntity not set");
      }
      
      relationshipNameProperty = new EntityProperty(relationshipEntity, PropertyType.NAME);
      
      relationshipFromProperty = new EntityProperty(relationshipEntity, PropertyType.RELATIONSHIP_FROM);
      
      relationshipToProperty = new EntityProperty(relationshipEntity, PropertyType.RELATIONSHIP_TO);
      
      relationshipTypeProperty = new EntityProperty(relationshipEntity, PropertyType.TYPE);
      
      if (!String.class.equals(relationshipTypeProperty.getPropertyType()))
      {
         relationshipTypeEntity = (Class<?>) relationshipTypeProperty.getPropertyType(); 
         relationshipTypeNameProperty = new EntityProperty(relationshipTypeEntity, PropertyType.NAME);
      }
      
  
   }
   
   protected void configureAttributes()
   {
      
   }
   
   
   public Class<?> getIdentityObjectEntity()
   {
      return identityObjectEntity;
   }
   
   public void setIdentityObjectEntity(Class<?> identityObjectEntity)
   {
      this.identityObjectEntity = identityObjectEntity;
   }
   
   public Class<?> getRelationshipEntity()
   {
      return relationshipEntity;
   }
   
   public void setRelationshipEntity(Class<?> relationshipEntity)
   {
      this.relationshipEntity = relationshipEntity;
   }
   
   public Class<?> getCredentialEntity()
   {
      return credentialEntity;
   }
   
   public void setCredentialEntity(Class<?> credentialEntity)
   {
      this.credentialEntity = credentialEntity;
   }
   
   public Class<?> getAttributeEntity()
   {
      return attributeEntity;
   }
   
   public void setAttributeEntity(Class<?> attributeEntity)
   {
      this.attributeEntity = attributeEntity;
   }
   
   public Class<?> getRoleTypeEntity()
   {
      return roleTypeEntity;
   }
   
   public void setRoleTypeEntity(Class<?> roleTypeEntity)
   {
      this.roleTypeEntity = roleTypeEntity;
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
   @Inject CredentialEncoder credentialEncoder;
   
   public boolean createUser(String username, Credential credential,
         Map<String, ?> attributes)
   {      
      try
      {
         if (getIdentityObjectEntity() == null)
         {
            throw new IdentityManagementException("Could not create user, identityObjectEntity not set.");
         }
         
         if (userExists(username))
         {
            log.warn("Could not create user, already exists.");
         }
         
         Object userInstance = getIdentityObjectEntity().newInstance();
         Object credentialInstance = null;
         
         identityNameProperty.setValue(userInstance, username);
         
         if (String.class.equals(identityTypeProperty.getPropertyType()))
         {
            identityTypeProperty.setValue(userInstance, userIdentityType);
         }
         else
         {
            identityTypeProperty.setValue(userInstance, lookupIdentityType(userIdentityType));
         }
         
         if (getCredentialEntity() == null)
         {
            // The credential must be stored in the identity object
            if (credentialValueProperty.isValid())
            {
               // TODO need to abstract this out
               credentialValueProperty.setValue(userInstance, credential);
            }

         }
         else
         {
            credentialInstance = getCredentialEntity().newInstance();
            credentialIdentityProperty.setValue(credentialInstance, userInstance);
            
            // TODO need to abstract this out
            credentialValueProperty.setValue(credentialInstance, credential);
            if (credentialTypeProperty.isValid())
            {
               // TODO set the credential type - need some kind of mapper?
               //credentialTypeProperty.setValue(credentialInstance, lookupCredentialType)
            }                        
         }
         
         // TODO create attributes
         
         entityManagerInstance.get().persist(userInstance);
         
         if (credentialInstance != null)
         {
            entityManagerInstance.get().persist(credentialInstance);
         }         
      }
      catch (Exception ex)
      {
         if (ex instanceof IdentityManagementException)
         {
            throw (IdentityManagementException) ex;
         }
         else
         {
            throw new IdentityManagementException("Could not create user.", ex);
         }
      }
      
      // TODO Auto-generated method stub
      return false;
   }   
   
   private Object lookupIdentityType(String identityType)
   {
      try
      {
         Object val = entityManagerInstance.get().createQuery(
               "select t from " + identityTypeEntity.getName() + " t where t." +
               identityTypeNameProperty.getName() + " = :identityType")
               .setParameter("identityType", identityType)
               .getSingleResult();
         return val;
      }
      catch (NoResultException ex)
      {
         return null;
      }
   }

   public boolean associateUser(String groupName, String groupType, String username)
   {
      return false;
   }
   
   public boolean disassociateUser(String groupName, String groupType, String username)
   {
      return false;
   }
   
   public boolean associateGroup(String groupName, String groupType, String memberGroupName, String memberGroupType)
   {
      return false;
   }
   
   public boolean disassociateGroup(String groupName, String groupType, String memberGroupName, String memberGroupType)
   {
      return false;
   }

   public boolean authenticate(String username, Credential credential)
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

   public boolean deleteUserAttribute(String username, String attribute)
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

   public List<String> findUsers(String filter)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean grantRole(String username, String roleType, String groupName,
         String groupType)
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

   public List<IdentityType> listRoleMembers(String roleType, String groupName,
         String groupType)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public List<String> listRoleTypes()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public boolean revokeRole(String username, String roleType,
         String groupName, String groupType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean roleTypeExists(String roleType)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean setUserAttribute(String username, String attribute,
         Object value)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean supportsFeature(Feature feature)
   {
      // TODO Auto-generated method stub
      return false;
   }

   public boolean updateCredential(String username, Credential credential)
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
