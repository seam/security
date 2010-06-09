package org.jboss.seam.security.management;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.NoResultException;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;
import org.jboss.seam.security.events.PrePersistUserEvent;
import org.jboss.seam.security.events.UserCreatedEvent;
import org.jboss.weld.extensions.util.properties.Property;
import org.jboss.weld.extensions.util.properties.query.AnnotatedPropertyCriteria;
import org.jboss.weld.extensions.util.properties.query.NamedPropertyCriteria;
import org.jboss.weld.extensions.util.properties.query.PropertyCriteria;
import org.jboss.weld.extensions.util.properties.query.PropertyQueries;
import org.jboss.weld.extensions.util.properties.query.TypedPropertyCriteria;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.spi.configuration.IdentityStoreConfigurationContext;
import org.picketlink.idm.spi.configuration.metadata.IdentityObjectAttributeMetaData;
import org.picketlink.idm.spi.exception.OperationNotSupportedException;
import org.picketlink.idm.spi.model.IdentityObject;
import org.picketlink.idm.spi.model.IdentityObjectAttribute;
import org.picketlink.idm.spi.model.IdentityObjectCredential;
import org.picketlink.idm.spi.model.IdentityObjectRelationship;
import org.picketlink.idm.spi.model.IdentityObjectRelationshipType;
import org.picketlink.idm.spi.model.IdentityObjectType;
import org.picketlink.idm.spi.search.IdentityObjectSearchCriteria;
import org.picketlink.idm.spi.store.FeaturesMetaData;
import org.picketlink.idm.spi.store.IdentityStoreInvocationContext;
import org.picketlink.idm.spi.store.IdentityStoreSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IdentityStore implementation that allows identity related data to be 
 * persisted in a database via JPA
 *  
 * @author Shane Bryzak
 */
public @ApplicationScoped class JpaIdentityStore implements org.picketlink.idm.spi.store.IdentityStore, Serializable
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
   
   private static final String PROPERTY_IDENTITY_ID = "IDENTITY_ID";
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
   private static final String PROPERTY_ATTRIBUTE_NAME = "ATTRIBUTE_NAME";
   private static final String PROPERTY_ATTRIBUTE_VALUE = "ATTRIBUTE_VALUE";
   private static final String PROPERTY_ROLE_TYPE_NAME = "ROLE_TYPE_NAME";
   
   /**
    * The bean manager
    */
   @Inject BeanManager beanManager;

   /**
    * 
    */
   @Inject Instance<EntityManager> entityManagerInstance;
   
   /**
    * 
    */
   //@Inject CredentialProcessor credentialEncoder;   
      
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
   
   /**
    * Attribute properties
    */
   private Map<String,Property<Object>> attributeProperties = new HashMap<String,Property<Object>>();
   
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
   
   public void bootstrap(IdentityStoreConfigurationContext configurationContext)
      throws IdentityException
   {
      if (identityClass == null)
      {
         throw new IdentityException(
               "Error initializing JpaIdentityStore - identityClass not set");
      }
      
      configureIdentityId();
      configureIdentityName();
      configureIdentityType();
      
      configureCredentials();
      configureRelationships();
      configureAttributes();   
   }   
   
   protected void configureIdentityId() throws IdentityException
   {
      List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
         .addCriteria(new AnnotatedPropertyCriteria(Id.class))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_IDENTITY_ID, props.get(0));
      }
      else
      {
         throw new IdentityException("Error initializing JpaIdentityStore - no Identity ID found.");
      }
   }
      
   protected void configureIdentityName() throws IdentityException
   {      
      List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
         .getResultList();
      
      if (props.size() == 1)
      {
         modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
      }
      else if (props.size() > 1)
      {
         throw new IdentityException(
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
         throw new IdentityException("Error initializing JpaIdentityStore - no valid identity name property found.");
      }
   }
   
   protected void configureIdentityType() throws IdentityException
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
         throw new IdentityException(
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
         throw new IdentityException("Error initializing JpaIdentityStore - no valid identity type property found.");
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
            throw new IdentityException("Error initializing JpaIdentityStore - no valid identity type name property found.");
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
   
   protected void configureCredentials() throws IdentityException
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
            throw new IdentityException(
                  "Ambiguous credential value property in credential class " + 
                  credentialClass.getName());
         }
         else
         {
            // Try scanning for a credential property also
            props = PropertyQueries.createQuery(credentialClass)
               .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL))
               .getResultList();
            if (props.size() == 1)
            {
               modelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
            }
            else if (props.size() > 1)
            {
               throw new IdentityException(
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
      }
      else
      {
         // The credentials may be stored in the identity class         
         List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityException(
                  "Ambiguous credential property in identity class " +
                  identityClass.getName());
         }
         else
         {         
            Property<Object> p = findNamedProperty(identityClass, "credentialValue", 
                  "password", "passwordHash", "credential", "value");
            if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
         }
      }
            
      if (!modelProperties.containsKey(PROPERTY_CREDENTIAL_VALUE))
      {
         throw new IdentityException("Error initializing JpaIdentityStore - no credential value property found.");
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
         throw new IdentityException(
               "Ambiguous credential type property in credential class " + 
               credentialClass.getName());
      }
      else
      {
         props = PropertyQueries.createQuery(credentialClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL_TYPE))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityException(
                  "Ambiguous credential type property in credential class " + 
                  credentialClass.getName());            
         }
         else
         {         
            Property<Object> p = findNamedProperty(credentialClass, "credentialType", 
                  "identityObjectCredentialType", "type");
            if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_TYPE, p);
         }
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
            throw new IdentityException("Error initializing JpaIdentityStore - no valid credential type name property found.");
         }
      }       
   }
   
   protected void configureRelationships() throws IdentityException
   {
      if (relationshipClass == null)
      {
         throw new IdentityException("Error initializing JpaIdentityStore - relationshipClass not set.");
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
         throw new IdentityException(
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
         throw new IdentityException(
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
         throw new IdentityException(
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
         throw new IdentityException(
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
         throw new IdentityException(
            "Error initializing JpaIdentityStore - no valid relationship from property found.");
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TO))
      {
         throw new IdentityException(
            "Error initializing JpaIdentityStore - no valid relationship to property found.");
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE))
      {
         throw new IdentityException(
            "Error initializing JpaIdentityStore - no valid relationship type property found.");
      }
      
      if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_NAME))
      {
         throw new IdentityException(
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
            throw new IdentityException(
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
            throw new IdentityException(
                  "Error initializing JpaIdentityStore - no valid relationship type name property found");
         }
      }      
   }
   
   protected void configureAttributes() throws IdentityException
   {
      // If an attribute class has been configured, scan it for attributes
      if (attributeClass != null)
      {
         List<Property<Object>> props = PropertyQueries.createQuery(attributeClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
            .addCriteria(new TypedPropertyCriteria(String.class))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_ATTRIBUTE_NAME, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityException(
            		"Ambiguous attribute name property in class " +
            		attributeClass.getName());
         }
         else
         {
            Property<Object> prop = findNamedProperty(attributeClass,
                  "attributeName", "name");
            if (prop != null) modelProperties.put(PROPERTY_ATTRIBUTE_NAME, prop);
         }
         
         props = PropertyQueries.createQuery(attributeClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.VALUE))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_ATTRIBUTE_VALUE, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityException(
                  "Ambiguous attribute value property in class " +
                  attributeClass.getName());
         }
         else
         {
            Property<Object> prop = findNamedProperty(attributeClass, 
                  "attributeValue", "value");
            if (prop != null) modelProperties.put(PROPERTY_ATTRIBUTE_VALUE, prop);
         }
      }

      // Scan for additional attributes in the identity class also
      List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
         .addCriteria(new PropertyTypeCriteria(PropertyType.ATTRIBUTE))
         .getResultList();
   
      for (Property<Object> p : props)
      {
         attributeProperties.put(
               p.getAnnotatedElement().getAnnotation(IdentityProperty.class).attributeName(), 
               p);
      }
      
      // scan any entity classes referenced by the identity class also
      props = PropertyQueries.createQuery(identityClass)
         .getResultList();
      
      for (Property<Object> p : props)
      {
         if (p.getJavaClass().isAnnotationPresent(Entity.class))
         {
            List<Property<Object>> pp = PropertyQueries.createQuery(p.getJavaClass())
               .addCriteria(new PropertyTypeCriteria(PropertyType.ATTRIBUTE))
               .getResultList();
            
            for (Property<Object> attributeProperty : pp)
            {
               attributeProperties.put(
                     attributeProperty.getAnnotatedElement().getAnnotation(IdentityProperty.class).attributeName(), 
                     attributeProperty);                        
            }
         }
      }
   }
   
   protected void configureRoleTypeNames()
   {
      if (roleTypeClass != null)
      {
         List<Property<Object>> props = PropertyQueries.createQuery(roleTypeClass)
            .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_ROLE_TYPE_NAME, props.get(0));
         }
      }
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

   public IdentityObject createIdentityObject(
         IdentityStoreInvocationContext invocationCtx, String name,
         IdentityObjectType identityObjectType) throws IdentityException
   {
      return createIdentityObject(invocationCtx, name, identityObjectType, null);
   }
   
   protected Object lookupIdentityType(String identityType) throws IdentityException
   {      
      try
      {
         Property<Object> typeNameProp = modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME);
         
         Object val = entityManagerInstance.get().createQuery(
               "select t from " + typeNameProp.getDeclaringClass().getName() + 
               " t where t." + typeNameProp.getName() +
                " = :identityType")
               .setParameter("identityType", identityType)
               .getSingleResult();
         return val;
      }
      catch (NoResultException ex)
      {
         throw new IdentityException("Could not determine identity type [" + identityType + "]");
      }      
   }

   public IdentityObject createIdentityObject(
         IdentityStoreInvocationContext invocationCtx, String name,
         IdentityObjectType identityObjectType, Map<String, String[]> attributes)
         throws IdentityException
   {
      try
      {
         Object identityInstance = identityClass.newInstance();
         modelProperties.get(PROPERTY_IDENTITY_NAME).setValue(identityInstance, name);
         
         Property<Object> typeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE); 
         
         if (String.class.equals(typeProp.getJavaClass()))
         {
            typeProp.setValue(identityInstance, identityObjectType.getName());
         }
         else
         {
            typeProp.setValue(identityInstance, lookupIdentityType(identityObjectType.getName()));
         }
               
         beanManager.fireEvent(new PrePersistUserEvent(identityInstance));
         
         entityManagerInstance.get().persist(identityInstance);
         
         beanManager.fireEvent(new UserCreatedEvent(identityInstance));
         
         // TODO persist attributes

         IdentityObject obj = new IdentityObjectImpl(
               modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identityInstance).toString(),
               name, identityObjectType);

         return obj;
      }
      catch (Exception ex)
      {
         throw new IdentityException("Error creating identity object", ex);
      }    
   }

   public IdentityObjectRelationship createRelationship(
         IdentityStoreInvocationContext invocationCxt,
         IdentityObject fromIdentity, IdentityObject toIdentity,
         IdentityObjectRelationshipType relationshipType,
         String relationshipName, boolean createNames) throws IdentityException
   {
      try
      {
         Object relationship = relationshipClass.newInstance();
         
         modelProperties.get(PROPERTY_RELATIONSHIP_FROM).setValue(relationship, 
               lookupIdentity(fromIdentity));
         modelProperties.get(PROPERTY_RELATIONSHIP_TO).setValue(relationship,
               lookupIdentity(toIdentity));
         
         Property<Object> type = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);
         if (String.class.equals(modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getJavaClass()))
         {
            type.setValue(relationship, relationshipType.getName());
         }
         else
         {
            type.setValue(relationship, lookupRelationshipType(relationshipType));
         }
         
         modelProperties.get(PROPERTY_RELATIONSHIP_NAME).setValue(relationship, 
               relationshipName);
         
         entityManagerInstance.get().persist(relationship);
         
         return new IdentityObjectRelationshipImpl(fromIdentity, toIdentity,
               relationshipName, relationshipType);
      }
      catch (Exception ex)
      {
         throw new IdentityException("Exception creating relationship", ex);
      }
   }
   
   protected Object lookupIdentity(IdentityObject obj)
   {
      // TODO implement
      return null;
      
   }
   
   protected Object lookupRelationshipType(IdentityObjectRelationshipType relationshipType)
   {
      // TODO implement
      return null;
   }

   public String createRelationshipName(IdentityStoreInvocationContext ctx,
         String name) throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public IdentityObject findIdentityObject(
         IdentityStoreInvocationContext invocationContext, String id)
         throws IdentityException
   {
      try
      {
        Object identity = entityManagerInstance.get().createQuery("select i from " +
              identityClass.getName() + " i where i." +
              modelProperties.get(PROPERTY_IDENTITY_ID).getName() +
              " = :id")
              .setParameter("id", id)
              .getSingleResult();
        
        IdentityObjectType type = modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME) ?
              new IdentityObjectTypeImpl(
                    modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME).getValue(
                          modelProperties.get(PROPERTY_IDENTITY_TYPE).getValue(identity)).toString()) :
              new IdentityObjectTypeImpl(modelProperties.get(PROPERTY_IDENTITY_TYPE).getValue(identity).toString());
        
        
        return new IdentityObjectImpl(
                  modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identity).toString(),
                  modelProperties.get(PROPERTY_IDENTITY_NAME).getValue(identity).toString(),
                  type);
      }
      catch (NoResultException ex)
      {
         return null;
      }
   }
   
   protected IdentityObjectType convertType(Object obj)
   {
      // TODO implement
      return null;
   }

   public IdentityObject findIdentityObject(
         IdentityStoreInvocationContext invocationContext, String name,
         IdentityObjectType identityObjectType) throws IdentityException
   {
      try
      {
         Object identityType = modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME) ?
               lookupIdentityType(identityObjectType.getName()) : 
                  identityObjectType.getName();
         
         Object identity = entityManagerInstance.get().createQuery("select i from " +
              identityClass.getName() + " i where i." +
              modelProperties.get(PROPERTY_IDENTITY_NAME).getName() +
              " = :name and i." + modelProperties.get(PROPERTY_IDENTITY_TYPE).getName() + 
              " = :type")
              .setParameter("name", name)
              .setParameter("type", identityType)              
              .getSingleResult();        
        
        return new IdentityObjectImpl(
                  modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identity).toString(),
                  modelProperties.get(PROPERTY_IDENTITY_NAME).getValue(identity).toString(),
                  identityObjectType);
      }
      catch (NoResultException ex)
      {
         return null;
      }
   }

   public Collection<IdentityObject> findIdentityObject(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObjectType identityType, IdentityObjectSearchCriteria criteria)
         throws IdentityException
   {
      
      // TODO Auto-generated method stub
      return null;
   }

   public Collection<IdentityObject> findIdentityObject(
         IdentityStoreInvocationContext invocationCxt, IdentityObject identity,
         IdentityObjectRelationshipType relationshipType, boolean parent,
         IdentityObjectSearchCriteria criteria) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public String getId()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public int getIdentityObjectsCount(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObjectType identityType) throws IdentityException
   {
      // TODO Auto-generated method stub
      return 0;
   }

   public Map<String, String> getRelationshipNameProperties(
         IdentityStoreInvocationContext ctx, String name)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Set<String> getRelationshipNames(IdentityStoreInvocationContext ctx,
         IdentityObjectSearchCriteria criteria) throws IdentityException,
         OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Set<String> getRelationshipNames(IdentityStoreInvocationContext ctx,
         IdentityObject identity, IdentityObjectSearchCriteria criteria)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Map<String, String> getRelationshipProperties(
         IdentityStoreInvocationContext ctx,
         IdentityObjectRelationship relationship) throws IdentityException,
         OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public FeaturesMetaData getSupportedFeatures()
   {
      // TODO Auto-generated method stub
      return null;
   }

   public void removeIdentityObject(
         IdentityStoreInvocationContext invocationCtx, IdentityObject identity)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public void removeRelationship(IdentityStoreInvocationContext invocationCxt,
         IdentityObject fromIdentity, IdentityObject toIdentity,
         IdentityObjectRelationshipType relationshipType,
         String relationshipName) throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public String removeRelationshipName(IdentityStoreInvocationContext ctx,
         String name) throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public void removeRelationshipNameProperties(
         IdentityStoreInvocationContext ctx, String name, Set<String> properties)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      
   }

   public void removeRelationshipProperties(IdentityStoreInvocationContext ctx,
         IdentityObjectRelationship relationship, Set<String> properties)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      
   }

   public void removeRelationships(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObject identity1, IdentityObject identity2, boolean named)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public Set<IdentityObjectRelationship> resolveRelationships(
         IdentityStoreInvocationContext invocationCxt,
         IdentityObject fromIdentity, IdentityObject toIdentity,
         IdentityObjectRelationshipType relationshipType)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Set<IdentityObjectRelationship> resolveRelationships(
         IdentityStoreInvocationContext invocationCxt, IdentityObject identity,
         IdentityObjectRelationshipType relationshipType, boolean parent,
         boolean named, String name) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public void setRelationshipNameProperties(
         IdentityStoreInvocationContext ctx, String name,
         Map<String, String> properties) throws IdentityException,
         OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      
   }

   public void setRelationshipProperties(IdentityStoreInvocationContext ctx,
         IdentityObjectRelationship relationship, Map<String, String> properties)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      
   }

   public void updateCredential(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, IdentityObjectCredential credential)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public boolean validateCredential(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, IdentityObjectCredential credential)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      return false;
   }

   public void addAttributes(IdentityStoreInvocationContext invocationCtx,
         IdentityObject identity, IdentityObjectAttribute[] attributes)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public IdentityObject findIdentityObjectByUniqueAttribute(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObjectType identityObjectType,
         IdentityObjectAttribute attribute) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public IdentityObjectAttribute getAttribute(
         IdentityStoreInvocationContext invocationContext,
         IdentityObject identity, String name) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Map<String, IdentityObjectAttribute> getAttributes(
         IdentityStoreInvocationContext invocationContext,
         IdentityObject identity) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Map<String, IdentityObjectAttributeMetaData> getAttributesMetaData(
         IdentityStoreInvocationContext invocationContext,
         IdentityObjectType identityType)
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Set<String> getSupportedAttributeNames(
         IdentityStoreInvocationContext invocationContext,
         IdentityObjectType identityType) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public void removeAttributes(IdentityStoreInvocationContext invocationCtx,
         IdentityObject identity, String[] attributeNames)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public void updateAttributes(IdentityStoreInvocationContext invocationCtx,
         IdentityObject identity, IdentityObjectAttribute[] attributes)
         throws IdentityException
   {
      // TODO Auto-generated method stub
      
   }

   public IdentityStoreSession createIdentityStoreSession()
         throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }
}
