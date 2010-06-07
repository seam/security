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
   private static final String PROPERTY_CREDENTIAL_VALUE = "CREDENTIAL_VALUE";
   private static final String PROPERTY_CREDENTIAL_TYPE = "CREDENTIAL_TYPE";
   private static final String PROPERTY_CREDENTIAL_TYPE_NAME = "CREDENTIAL_TYPE_NAME";
   private static final String PROPERTY_RELATIONSHIP_FROM = "RELATIONSHIP_FROM";
   private static final String PROPERTY_RELATIONSHIP_TO = "RELATIONSHIP_TO";
   private static final String PROPERTY_RELATIONSHIP_TYPE = "RELATIONSHIP_TYPE";
   private static final String PROPERTY_RELATIONSHIP_TYPE_NAME = "RELATIONSHIP_TYPE_NAME";
   private static final String PROPERTY_RELATIONSHIP_NAME = "RELATIONSHIP_NAME";
      
   // Entity classes
   
   private Class<?> identityClass;
   private Class<?> credentialClass;
   private Class<?> relationshipClass;   
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
   private Map<String,Property<Object>> modelProperties = new HashMap<String,Property<Object>>();   
   
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
      
      List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
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
         Property<Object> p = findNamedProperty(identityClass, "username", "userName", "name");
         if (p != null) 
         {
            modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
         }
         else 
         {
            // Last resort - check whether the entity class exposes a single String property
            // if so, let's assume it's the identity name
            props = PropertyQueries.createQuery(identityClass)
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
         Property<Object> p = findNamedProperty(identityClass, "identityObjectType", 
               "identityType", "identityObjectTypeName", "identityTypeName", 
               "typeName", "discriminator", "accountType", "userType", "type");
         if (p != null) 
         {
            modelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
         }
         else 
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
                  Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                        "identityObjectTypeName", "identityTypeName", "typeName", "name");
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
         Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
               "identityObjectTypeName", "identityTypeName", "typeName", "name");
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
   
   protected Property<Object> findNamedProperty(Class<?> targetClass, String... allowedNames)
   {
      List<Property<Object>> props = PropertyQueries.createQuery(targetClass)
         .addCriteria(new TypedPropertyCriteria(String.class))
         .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
         .getResultList();
      
      if (props.size() == 1)
      {
         return props.get(0);
      }
      else
      {
         props = PropertyQueries.createQuery(targetClass)
            .addCriteria(new TypedPropertyCriteria(String.class))
            .addCriteria(new NamedPropertyCriteria(allowedNames))
            .getResultList();
         
         for (String name : allowedNames)
         {
            for (Property<Object> prop : props)
            {
               if (name.equals(prop.getName())) return prop;
            }
         }
      }      
      
      return null;
   }
   
   protected void configureCredentials()
   {
      // If a credential entity has been explicitly configured, scan it
      if (credentialClass != null)
      {
         List<Property<Object>> props = PropertyQueries.createQuery(credentialClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.VALUE))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityManagementException(
                  "Ambiguous credential value property in credential class " + 
                  credentialClass.getName());
         }
         else
         {
            Property<Object> p = findNamedProperty(credentialClass, "credentialValue", 
                  "password", "passwordHash", "credential", "value");
            if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
         }  
      }
      else
      {
         // The credentials may be stored in the identity class - let's search for it by name
         Property<Object> p = findNamedProperty(identityClass, "credentialValue", 
               "password", "passwordHash", "credential", "value");
         if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
      }
            
      if (!modelProperties.containsKey(PROPERTY_CREDENTIAL_VALUE))
      {
         throw new IdentityManagementException("Error initializing JpaIdentityStore - no credential value property found.");
      }            
            
      // Scan for a credential type property
      List<Property<Object>> props = PropertyQueries.createQuery(credentialClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous credential type property in credential class " + 
               credentialClass.getName());
      }
      else
      {
         Property<Object> p = findNamedProperty(credentialClass, "credentialType", 
               "identityObjectCredentialType", "type");
         if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_TYPE, p);
      }      

      Property<?> typeProp = modelProperties.get(PROPERTY_CREDENTIAL_TYPE);      
      
      // If the credential type property isn't a String, then validate the lookup type
      if (!String.class.equals(typeProp.getJavaClass()))
      {
         Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
               "credentialObjectTypeName", "credentialTypeName", "typeName", "name");
         if (nameProp != null)
         {
            modelProperties.put(PROPERTY_CREDENTIAL_TYPE_NAME, nameProp);
         }
         else
         {
            throw new IdentityManagementException("Error initializing JpaIdentityStore - no valid credential type name property found.");
         }
      }       
   }
   
   protected void configureRelationships()
   {
      if (relationshipClass == null)
      {
         throw new IdentityManagementException("Error initializing JpaIdentityStore - relationshipClass not set.");
      }
      
      List<Property<Object>> props = PropertyQueries.createQuery(relationshipClass)
         .addCriteria(new TypedPropertyCriteria(identityClass))
         .addCriteria(new PropertyTypeCriteria(PropertyType.RELATIONSHIP_FROM))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_RELATIONSHIP_FROM, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous relationshipFrom property in relationship class " + 
               relationshipClass.getName());
      }
      else
      {
         Property<Object> p = findNamedProperty(relationshipClass, "relationshipFrom", 
               "fromIdentityObject", "fromIdentity");
         if (p != null) 
         {
            modelProperties.put(PROPERTY_RELATIONSHIP_FROM, p);
         }
         else
         {
            // Last resort - search for a property with a type of identityClass
            // and a "from" in its name
            props = PropertyQueries.createQuery(relationshipClass)
               .addCriteria(new TypedPropertyCriteria(identityClass))
               .getResultList();
            
            for (Property<Object> prop : props)
            {
               if (prop.getName().contains("from"))
               {
                  modelProperties.put(PROPERTY_RELATIONSHIP_FROM, prop);
                  break;
               }
            }
         }         
      }
  
      
      props = PropertyQueries.createQuery(relationshipClass)
         .addCriteria(new TypedPropertyCriteria(identityClass))
         .addCriteria(new PropertyTypeCriteria(PropertyType.RELATIONSHIP_TO))
         .getResultList();
   
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_RELATIONSHIP_TO, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous relationshipTo property in relationship class " + 
               relationshipClass.getName());
      }
      else
      {
         Property<Object> p = findNamedProperty(relationshipClass, "relationshipTo", 
               "toIdentityObject", "toIdentity");
         if (p != null) 
         {
            modelProperties.put(PROPERTY_RELATIONSHIP_TO, p);
         }
         else
         {
            // Last resort - search for a property with a type of identityClass
            // and a "to" in its name
            props = PropertyQueries.createQuery(relationshipClass)
               .addCriteria(new TypedPropertyCriteria(identityClass))
               .getResultList();
            
            for (Property<Object> prop : props)
            {
               if (prop.getName().contains("to"))
               {
                  modelProperties.put(PROPERTY_RELATIONSHIP_TO, prop);
                  break;
               }
            }
         }         
      }      
      
      props = PropertyQueries.createQuery(relationshipClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
         .getResultList();
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_RELATIONSHIP_TYPE, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous relationshipType property in relationship class " +
               relationshipClass.getName());
      }
      else
      {
         Property<Object> p = findNamedProperty(relationshipClass, 
               "identityRelationshipType", "relationshipType", "type");
         if (p != null)
         {
            modelProperties.put(PROPERTY_RELATIONSHIP_TYPE, p);
         }
         else
         {
            props = PropertyQueries.createQuery(relationshipClass)
               .getResultList();
            for (Property<Object> prop : props)
            {
               if (prop.getName().contains("type"))
               {
                  modelProperties.put(PROPERTY_RELATIONSHIP_TYPE, prop);
                  break;
               }
            }
         }
      }
      
      props = PropertyQueries.createQuery(relationshipClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
         .addCriteria(new TypedPropertyCriteria(String.class))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_RELATIONSHIP_NAME, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityManagementException(
               "Ambiguous relationship name property in relationship class " +
               relationshipClass.getName());
      }
      else
      {
         Property<Object> p = findNamedProperty(relationshipClass,
               "relationshipName", "name");
         if (p != null)
         {
            modelProperties.put(PROPERTY_RELATIONSHIP_NAME, p);
         }
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_FROM))
      {
         throw new IdentityManagementException(
            "Error initializing JpaIdentityStore - no valid relationship from property found.");
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TO))
      {
         throw new IdentityManagementException(
            "Error initializing JpaIdentityStore - no valid relationship to property found.");
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE))
      {
         throw new IdentityManagementException(
            "Error initializing JpaIdentityStore - no valid relationship type property found.");
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_NAME))
      {
         throw new IdentityManagementException(
            "Error initializing JpaIdentityStore - no valid relationship name property found.");
      }
      
      Class<?> typeClass = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getJavaClass();
      if (!String.class.equals(typeClass))
      {
         props = PropertyQueries.createQuery(typeClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
            .addCriteria(new TypedPropertyCriteria(String.class))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_RELATIONSHIP_TYPE_NAME, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityManagementException(
                  "Ambiguous relationship type name property in class " +
                  typeClass.getName());
         }
         else
         {
            Property<Object> p = findNamedProperty(typeClass, "relationshipTypeName",
                  "typeName", "name");
            if (p != null)
            {
               modelProperties.put(PROPERTY_RELATIONSHIP_TYPE_NAME, p);
            }
         }
         
         if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE_NAME))
         {
            throw new IdentityManagementException(
                  "Error initializing JpaIdentityStore - no valid relationship type name property found");
         }
      }      
   }
   
   protected void configureAttributes()
   {
      
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
         if (identityClass == null)
         {
            throw new IdentityManagementException("Could not create user, identityObjectEntity not set.");
         }
         
         if (userExists(username))
         {
            log.warn("Could not create user, already exists.");
         }
         
         Object userInstance = identityClass.newInstance();
         Object credentialInstance = null;
         
         modelProperties.get(PROPERTY_IDENTITY_NAME).setValue(userInstance, username);
         
         Property<Object> identityType = modelProperties.get(PROPERTY_IDENTITY_TYPE);
         if (String.class.equals(identityType.getJavaClass()))
         {
            identityType.setValue(userInstance, userIdentityType);
         }
         else
         {
            identityType.setValue(userInstance, lookupIdentityType(userIdentityType));
         }
         
         if (credentialClass == null)
         {
            modelProperties.get(PROPERTY_CREDENTIAL_VALUE).setValue(userInstance, credential);
         }
         else
         {
            credentialInstance = credentialClass.newInstance();
            // TODO implement this
            //credentialIdentityProperty.setValue(credentialInstance, userInstance);
            
            // TODO need to abstract this out
            modelProperties.get(PROPERTY_CREDENTIAL_VALUE).setValue(credentialInstance, credential);
            if (modelProperties.containsKey(PROPERTY_CREDENTIAL_TYPE))
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
               "select t from " + identityClass.getName() + " t where t." +
               modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME).getName() +
                " = :identityType")
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
