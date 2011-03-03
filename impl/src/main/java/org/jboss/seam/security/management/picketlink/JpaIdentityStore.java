package org.jboss.seam.security.management.picketlink;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.NoResultException;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;
import org.jboss.seam.security.management.IdentityObjectImpl;
import org.jboss.seam.security.management.IdentityObjectRelationshipImpl;
import org.jboss.seam.security.management.IdentityObjectRelationshipTypeImpl;
import org.jboss.seam.security.management.IdentityObjectTypeImpl;
import org.jboss.seam.solder.properties.Property;
import org.jboss.seam.solder.properties.query.AnnotatedPropertyCriteria;
import org.jboss.seam.solder.properties.query.NamedPropertyCriteria;
import org.jboss.seam.solder.properties.query.PropertyCriteria;
import org.jboss.seam.solder.properties.query.PropertyQueries;
import org.jboss.seam.solder.properties.query.TypedPropertyCriteria;
import org.jboss.seam.solder.reflection.Reflections;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.api.SimpleAttribute;
import org.picketlink.idm.impl.store.FeaturesMetaDataImpl;
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
import org.picketlink.idm.spi.store.IdentityObjectSearchCriteriaType;
import org.picketlink.idm.spi.store.IdentityStoreInvocationContext;
import org.picketlink.idm.spi.store.IdentityStoreSession;

/**
 * IdentityStore implementation that allows identity related data to be 
 * persisted in a database via JPA
 *  
 * @author Shane Bryzak
 */
public class JpaIdentityStore implements org.picketlink.idm.spi.store.IdentityStore, Serializable
{
   private static final long serialVersionUID = 7729139146633529501L;
   
   public static final String OPTION_IDENTITY_CLASS_NAME = "identityEntityClassName";
   public static final String OPTION_CREDENTIAL_CLASS_NAME = "credentialEntityClassName";
   public static final String OPTION_RELATIONSHIP_CLASS_NAME = "relationshipEntityClassName";
   public static final String OPTION_ROLE_TYPE_CLASS_NAME = "roleTypeEntityClassName";
   public static final String OPTION_ATTRIBUTE_CLASS_NAME = "attributeEntityClassName";
   
   private static final String DEFAULT_USER_IDENTITY_TYPE = "USER";
   private static final String DEFAULT_ROLE_IDENTITY_TYPE = "ROLE";
   private static final String DEFAULT_GROUP_IDENTITY_TYPE = "GROUP";   
   
   private static final String DEFAULT_RELATIONSHIP_TYPE_MEMBERSHIP = "MEMBERSHIP";
   private static final String DEFAULT_RELATIONSHIP_TYPE_ROLE = "ROLE";

   // Property keys
   
   private static final String PROPERTY_IDENTITY_ID = "IDENTITY_ID";
   private static final String PROPERTY_IDENTITY_NAME = "IDENTITY_NAME";
   private static final String PROPERTY_IDENTITY_TYPE = "IDENTITY_TYPE";
   private static final String PROPERTY_IDENTITY_TYPE_NAME = "IDENTITY_TYPE_NAME";
   private static final String PROPERTY_CREDENTIAL_VALUE = "CREDENTIAL_VALUE";
   private static final String PROPERTY_CREDENTIAL_TYPE = "CREDENTIAL_TYPE";
   private static final String PROPERTY_CREDENTIAL_TYPE_NAME = "CREDENTIAL_TYPE_NAME";
   private static final String PROPERTY_CREDENTIAL_IDENTITY = "CREDENTIAL_IDENTITY";
   private static final String PROPERTY_RELATIONSHIP_FROM = "RELATIONSHIP_FROM";
   private static final String PROPERTY_RELATIONSHIP_TO = "RELATIONSHIP_TO";
   private static final String PROPERTY_RELATIONSHIP_TYPE = "RELATIONSHIP_TYPE";
   private static final String PROPERTY_RELATIONSHIP_TYPE_NAME = "RELATIONSHIP_TYPE_NAME";
   private static final String PROPERTY_RELATIONSHIP_NAME = "RELATIONSHIP_NAME";

   private static final String PROPERTY_ROLE_TYPE_NAME = "RELATIONSHIP_NAME_NAME";
   
   private static final String PROPERTY_ATTRIBUTE_NAME = "ATTRIBUTE_NAME";
   private static final String PROPERTY_ATTRIBUTE_VALUE = "ATTRIBUTE_VALUE";
   private static final String PROPERTY_ATTRIBUTE_IDENTITY = "ATTRIBUTE_IDENTITY";  
   
   private class EntityToSpiConverter
   {
      private static final String IDENTITY_TYPE_CACHE_PREFIX = "identity_type:";
      private static final String RELATIONSHIP_TYPE_CACHE_PREFIX = "relationship_type:";
      
      private Map<Object,Object> cache = new HashMap<Object,Object>();
      
      private Property<?> identityIdProperty = modelProperties.get(PROPERTY_IDENTITY_ID);
      private Property<?> identityNameProperty = modelProperties.get(PROPERTY_IDENTITY_NAME);
      private Property<?> identityTypeProperty = modelProperties.get(PROPERTY_IDENTITY_TYPE);
      private Property<?> identityTypeNameProperty = modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME);
      private Property<?> relationshipTypeNameProperty = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME);
      
      public IdentityObject convertToIdentityObject(Object entity)
      {
         if (!identityClass.isAssignableFrom(entity.getClass())) 
         {
            throw new IllegalArgumentException("Invalid identity entity");
         }
         
         if (cache.containsKey(entity))
         {
            return (IdentityObject) cache.get(entity);
         }
         else
         {         
            IdentityObject obj = new IdentityObjectImpl(
               identityIdProperty.getValue(entity).toString(),
               identityNameProperty.getValue(entity).toString(),
               convertToIdentityObjectType(identityTypeProperty.getValue(entity)));
            cache.put(entity, obj);
            
            return obj;            
         }
      }
      
      public IdentityObjectType convertToIdentityObjectType(Object value)
      {
         if (value instanceof String)
         {
            String key = IDENTITY_TYPE_CACHE_PREFIX + (String) value; 
            if (cache.containsKey(key)) return (IdentityObjectType) cache.get(key);
            
            IdentityObjectType type = new IdentityObjectTypeImpl((String) value);
            cache.put(key, type);
            return type;
         }
         else
         {
            if (cache.containsKey(value)) return (IdentityObjectType) cache.get(value);
            IdentityObjectType type = new IdentityObjectTypeImpl(
                  (String) identityTypeNameProperty.getValue(value));
            cache.put(value, type);
            return type;
         }
      }
      
      public IdentityObjectRelationshipType convertToRelationshipType(Object value)
      {
         if (value instanceof String)
         {
            String key = RELATIONSHIP_TYPE_CACHE_PREFIX + (String) value;
            if (cache.containsKey(key)) return (IdentityObjectRelationshipType) cache.get(key);
            
            IdentityObjectRelationshipType type = new IdentityObjectRelationshipTypeImpl((String) value);
            cache.put(key, type);
            return type;
         }
         else
         {
            if (cache.containsKey(value)) return (IdentityObjectRelationshipType) cache.get(value);
            IdentityObjectRelationshipType type = new IdentityObjectRelationshipTypeImpl(
                  (String) relationshipTypeNameProperty.getValue(value));
            cache.put(value, type);
            return type;
         }
      }
   }
   
   
   private String id;
      
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
   
   private FeaturesMetaData featuresMetaData;
   
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
   
   public JpaIdentityStore(String id)
   {
      this.id = id;
   }
   
   public void bootstrap(IdentityStoreConfigurationContext configurationContext)
      throws IdentityException
   {           
      String clsName = configurationContext.getStoreConfigurationMetaData()
         .getOptionSingleValue(OPTION_IDENTITY_CLASS_NAME);

      if (clsName == null)
      {
         throw new IdentityException("Error bootstrapping JpaIdentityStore - identity entity class cannot be null");
      }
      
      try
      {
         identityClass = Reflections.classForName(clsName);
      }
      catch (ClassNotFoundException e)
      {
         throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid identity entity class: " + clsName);
      }
      
      if (identityClass == null)
      {
         throw new IdentityException(
               "Error initializing JpaIdentityStore - identityClass not set");
      }
      
      clsName = configurationContext.getStoreConfigurationMetaData()
         .getOptionSingleValue(OPTION_CREDENTIAL_CLASS_NAME);
      
      if (clsName != null)
      {
         try
         {
            credentialClass = Class.forName(clsName);
         }
         catch (ClassNotFoundException e)
         {
            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid credential entity class: " + clsName);
         }
      }
      
      clsName = configurationContext.getStoreConfigurationMetaData()
         .getOptionSingleValue(OPTION_RELATIONSHIP_CLASS_NAME);
      
      try
      {
         relationshipClass = Class.forName(clsName);
      }
      catch (ClassNotFoundException e)
      {
         throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid relationship entity class: " + clsName);
      }      
      
      boolean namedRelationshipsSupported = false;
      
      clsName = configurationContext.getStoreConfigurationMetaData()
         .getOptionSingleValue(OPTION_ROLE_TYPE_CLASS_NAME);
      
      if (clsName != null)
      {
         try
         {
            roleTypeClass = Class.forName(clsName);
            namedRelationshipsSupported = true;
         }
         catch (ClassNotFoundException e)
         {
            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid role type entity class: " + clsName);
         }
      }
      
      clsName = configurationContext.getStoreConfigurationMetaData()
         .getOptionSingleValue(OPTION_ATTRIBUTE_CLASS_NAME);
      if (clsName != null)
      {
         try
         {
            attributeClass = Class.forName(clsName);
         }
         catch (ClassNotFoundException e)
         {
            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid attribute entity class: " + clsName);
         }
      }
      
      configureIdentityId();
      configureIdentityName();
      configureIdentityType();
      
      configureCredentials();
      configureRelationships();
      configureAttributes();   
      
      if (namedRelationshipsSupported)
      {
         configureRoleTypeName();
      }
      
      featuresMetaData = new FeaturesMetaDataImpl(
            configurationContext.getStoreConfigurationMetaData(),
            new HashSet<IdentityObjectSearchCriteriaType>(),
            false,
            namedRelationshipsSupported,
            new HashSet<String>()
            );            
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
            modelProperties.put(PROPERTY_IDENTITY_NAME, p);
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
         
         // Scan for the credential identity property
         props = PropertyQueries.createQuery(credentialClass)
            .addCriteria(new TypedPropertyCriteria(identityClass))
            .getResultList();
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_CREDENTIAL_IDENTITY, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityException(
                  "Ambiguous identity property in credential class " + 
                  credentialClass.getName());
         }
         else
         {
            // Scan for a named identity property
            props = PropertyQueries.createQuery(credentialClass)
               .addCriteria(new NamedPropertyCriteria("identity", "identityObject"))
               .getResultList();
            if (!props.isEmpty())
            {
               modelProperties.put(PROPERTY_CREDENTIAL_IDENTITY, props.get(0));
            }
            else
            {
               throw new IdentityException("Error initializing JpaIdentityStore - no credential identity property found.");
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
         
         props = PropertyQueries.createQuery(attributeClass)
            .addCriteria(new TypedPropertyCriteria(identityClass))
            .getResultList();
         
         if (props.size() == 1)
         {
            modelProperties.put(PROPERTY_ATTRIBUTE_IDENTITY, props.get(0));
         }
         else if (props.size() > 1)
         {
            throw new IdentityException(
                  "Ambiguous identity property in attribute class " +
                  attributeClass.getName());
         }
         else
         {
            throw new IdentityException("Error initializing JpaIdentityStore - " +
                  "no attribute identity property found.");
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
         if (!p.isReadOnly() && p.getJavaClass().isAnnotationPresent(Entity.class))
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
   
   protected void configureRoleTypeName()
   {
      Property<Object> relationshipNameProp = findNamedProperty(roleTypeClass, "name");
      if (relationshipNameProp != null)
      {         
         modelProperties.put(PROPERTY_ROLE_TYPE_NAME, relationshipNameProp);
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
   
   public IdentityStoreSession createIdentityStoreSession(
         Map<String, Object> sessionOptions) throws IdentityException
   {
      EntityManager em = (EntityManager) sessionOptions.get("ENTITY_MANAGER");
      
      return new JpaIdentityStoreSessionImpl(em);
   }

   public IdentityObject createIdentityObject(
         IdentityStoreInvocationContext invocationCtx, String name,
         IdentityObjectType identityObjectType) throws IdentityException
   {
      return createIdentityObject(invocationCtx, name, identityObjectType, null);
   }
   
   protected Object lookupIdentityType(String identityType, EntityManager em)
   {      
      try
      {
         Property<Object> typeNameProp = modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME);
         
         // If there is no identity type table, just return the name
         if (typeNameProp == null) return identityType;
         
         Object val = em.createQuery(
               "select t from " + typeNameProp.getDeclaringClass().getName() + 
               " t where t." + typeNameProp.getName() +
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

   public IdentityObject createIdentityObject(
         IdentityStoreInvocationContext ctx, String name,
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
            typeProp.setValue(identityInstance, lookupIdentityType(identityObjectType.getName(), 
                  getEntityManager(ctx)));
         }
               
         //beanManager.fireEvent(new PrePersistUserEvent(identityInstance));
         
         EntityManager em = getEntityManager(ctx);
         
         em.persist(identityInstance);
         
         //beanManager.fireEvent(new UserCreatedEvent(identityInstance));
         
         // TODO persist attributes

         Object id = modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identityInstance);
         IdentityObject obj = new IdentityObjectImpl(
               (id != null ? id.toString() : null),
               name, identityObjectType);

         return obj;
      }
      catch (Exception ex)
      {
         throw new IdentityException("Error creating identity object", ex);
      }    
   }

   public IdentityObjectRelationship createRelationship(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObject fromIdentity, IdentityObject toIdentity,
         IdentityObjectRelationshipType relationshipType,
         String relationshipName, boolean createNames) throws IdentityException
   {
      try
      {
         EntityManager em = getEntityManager(invocationCtx);
         
         Object relationship = relationshipClass.newInstance();
         
         modelProperties.get(PROPERTY_RELATIONSHIP_FROM).setValue(relationship, 
               lookupIdentity(fromIdentity, em));
         modelProperties.get(PROPERTY_RELATIONSHIP_TO).setValue(relationship,
               lookupIdentity(toIdentity, em));
         
         Property<Object> type = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);
         if (String.class.equals(modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getJavaClass()))
         {
            type.setValue(relationship, relationshipType.getName());
         }
         else
         {
            type.setValue(relationship, lookupRelationshipType(relationshipType, em));
         }
         
         modelProperties.get(PROPERTY_RELATIONSHIP_NAME).setValue(relationship, 
               relationshipName);
         
         em.persist(relationship);
         
         return new IdentityObjectRelationshipImpl(fromIdentity, toIdentity,
               relationshipName, relationshipType);
      }
      catch (Exception ex)
      {
         throw new IdentityException("Exception creating relationship", ex);
      }
   }
   
   protected Object lookupIdentity(IdentityObject obj, EntityManager em)
   {
      Property<?> identityNameProp = modelProperties.get(PROPERTY_IDENTITY_NAME);
      Property<?> identityTypeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(identityClass);
      Root<?> root = criteria.from(identityClass);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      predicates.add(builder.equal(root.get(identityNameProp.getName()), obj.getName()));
      predicates.add(builder.equal(root.get(identityTypeProp.getName()), lookupIdentityType(obj.getIdentityType().getName(), em)));
      
      // TODO add criteria for identity type
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      return em.createQuery(criteria).getSingleResult();
   }
   
   protected Object lookupCredentialTypeEntity(String name, EntityManager em)
   {
      Property<?> credentialTypeNameProp = modelProperties.get(PROPERTY_CREDENTIAL_TYPE_NAME);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(credentialTypeNameProp.getDeclaringClass());
      Root<?> root = criteria.from(credentialTypeNameProp.getDeclaringClass());
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      predicates.add(builder.equal(root.get(credentialTypeNameProp.getName()), name));      
      criteria.where(predicates.toArray(new Predicate[0]));

      return em.createQuery(criteria).getSingleResult();
   }
   
   protected Object lookupRelationshipType(IdentityObjectRelationshipType relationshipType, EntityManager em)
   {
      Property<?> relationshipTypeNameProp = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME);      
      
      if (relationshipTypeNameProp != null)
      {
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(relationshipTypeNameProp.getDeclaringClass());
         Root<?> root = criteria.from(relationshipTypeNameProp.getDeclaringClass());
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(relationshipTypeNameProp.getName()), relationshipType.getName()));      
         criteria.where(predicates.toArray(new Predicate[0]));

         return em.createQuery(criteria).getSingleResult();
      }
      else
      {
         return relationshipType.getName();
      }
   }

   public String createRelationshipName(IdentityStoreInvocationContext ctx,
         String name) throws IdentityException, OperationNotSupportedException
   {
      try
      {
         Property<Object> roleTypeNameProp = modelProperties.get(PROPERTY_ROLE_TYPE_NAME);
         
         Object roleTypeInstance = roleTypeClass.newInstance();
         roleTypeNameProp.setValue(roleTypeInstance, name);
         
         EntityManager em = getEntityManager(ctx);
         
         em.persist(roleTypeInstance);
         return name;
      }
      catch (Exception ex)
      {
         throw new IdentityException("Error creating relationship name", ex);
      }
   }
   
   public EntityManager getEntityManager(IdentityStoreInvocationContext invocationContext)
   {
      return ((JpaIdentityStoreSessionImpl) invocationContext.getIdentityStoreSession()).getEntityManager();
   }

   public IdentityObject findIdentityObject(IdentityStoreInvocationContext invocationContext, String id)
         throws IdentityException
   {
      try
      {
        Object identity = getEntityManager(invocationContext).createQuery("select i from " +
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

   public IdentityObject findIdentityObject(
         IdentityStoreInvocationContext invocationContext, String name,
         IdentityObjectType identityObjectType) throws IdentityException
   {
      try
      {
         Object identityType = modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME) ?
               lookupIdentityType(identityObjectType.getName(), getEntityManager(invocationContext)) : 
                  identityObjectType.getName();
         
         Object identity = getEntityManager(invocationContext).createQuery("select i from " +
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
         IdentityStoreInvocationContext ctx,
         IdentityObjectType identityType, IdentityObjectSearchCriteria searchCriteria)
         throws IdentityException
   {
      List<IdentityObject> objs = new ArrayList<IdentityObject>();
      
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(identityClass);
      
      Root<?> root = criteria.from(identityClass);

      Property<?> identityTypeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      
      if (identityType != null)
      {
         predicates.add(builder.equal(root.get(identityTypeProp.getName()), 
               lookupIdentityType(identityType.getName(), em)));
      }
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      List<?> results = em.createQuery(criteria).getResultList();
      
      EntityToSpiConverter converter = new EntityToSpiConverter();
      
      for (Object result : results)
      {               
         objs.add(converter.convertToIdentityObject(result));
      }
      
      return objs;
   }

   public Collection<IdentityObject> findIdentityObject(
         IdentityStoreInvocationContext invocationCxt, IdentityObject identity,
         IdentityObjectRelationshipType relationshipType, boolean parent,
         IdentityObjectSearchCriteria criteria) throws IdentityException
   {
      List<IdentityObject> objs = new ArrayList<IdentityObject>();
      
      System.out.println("*** Invoked unimplemented method findIdentityObject()");
      
      // TODO Auto-generated method stub
      return objs;
   }

   public String getId()
   {
      return id;
   }

   public int getIdentityObjectsCount(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObjectType identityType) throws IdentityException
   {
      System.out.println("*** Invoked unimplemented method getIdentityObjectsCount()");
      // TODO Auto-generated method stub
      return 0;
   }

   public Map<String, String> getRelationshipNameProperties(
         IdentityStoreInvocationContext ctx, String name)
         throws IdentityException, OperationNotSupportedException
   {
      System.out.println("*** Invoked unimplemented method getRelationshipNameProperties()");
      // TODO Auto-generated method stub
      return null;
   }

   public Set<String> getRelationshipNames(IdentityStoreInvocationContext ctx,
         IdentityObjectSearchCriteria searchCriteria) throws IdentityException,
         OperationNotSupportedException
   {
      Set<String> names = new HashSet<String>();
      
      Property<Object> roleTypeNameProp = modelProperties.get(PROPERTY_ROLE_TYPE_NAME);
      
      if (roleTypeClass != null)
      {
         EntityManager em = getEntityManager(ctx);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(roleTypeClass);
         criteria.from(roleTypeClass);
         
         List<?> results = em.createQuery(criteria).getResultList();
         for (Object result : results)
         {
            names.add(roleTypeNameProp.getValue(result).toString());
         }
      }      

      return names;
   }

   public Set<String> getRelationshipNames(IdentityStoreInvocationContext ctx,
         IdentityObject identity, IdentityObjectSearchCriteria searchCriteria)
         throws IdentityException, OperationNotSupportedException
   {
      Set<String> names = new HashSet<String>();
      
      if (!featuresMetaData.isNamedRelationshipsSupported()) return names;
      
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(relationshipClass);
      Root<?> root = criteria.from(relationshipClass);
      
      Property<?> identityToProperty = modelProperties.get(PROPERTY_RELATIONSHIP_TO);
      Property<?> relationshipNameProperty = modelProperties.get(PROPERTY_RELATIONSHIP_NAME);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      predicates.add(builder.equal(root.get(identityToProperty.getName()), 
            lookupIdentity(identity, em)));
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      List<?> results = em.createQuery(criteria).getResultList();
      for (Object result : results)
      {
         names.add((String) relationshipNameProperty.getValue(result));
      }
      
      return names;
   }

   public Map<String, String> getRelationshipProperties(
         IdentityStoreInvocationContext ctx,
         IdentityObjectRelationship relationship) throws IdentityException,
         OperationNotSupportedException
   {
      System.out.println("*** Invoked unimplemented method getRelationshipProperties()");
      // TODO Auto-generated method stub
      return null;
   }

   public FeaturesMetaData getSupportedFeatures()
   {      
      return featuresMetaData;
   }

   public void removeIdentityObject(
         IdentityStoreInvocationContext ctx, IdentityObject identity)
         throws IdentityException
   {
      removeRelationships(ctx, identity, null, false);
      
      Property<?> nameProperty = modelProperties.get(PROPERTY_IDENTITY_NAME);
      Property<?> typeProperty = modelProperties.get(PROPERTY_IDENTITY_TYPE);
      
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      
      CriteriaQuery<?> criteria = builder.createQuery(identityClass);
      Root<?> root = criteria.from(identityClass);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      predicates.add(builder.equal(root.get(nameProperty.getName()), 
            identity.getName()));
      predicates.add(builder.equal(root.get(typeProperty.getName()),
            lookupIdentityType(identity.getIdentityType().getName(), em)));
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      try
      {
         Object instance = em.createQuery(criteria).getSingleResult();
                  
         // If there is a credential class, delete any credentials
         if (credentialClass != null)
         {
            Property<?> credentialIdentityProp = modelProperties.get(PROPERTY_CREDENTIAL_IDENTITY);
            
            criteria = builder.createQuery(credentialClass);
            root = criteria.from(credentialClass);
            
            predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(credentialIdentityProp.getName()),
                  lookupIdentity(identity, em)));
            criteria.where(predicates.toArray(new Predicate[0]));
            
            List<?> results = em.createQuery(criteria).getResultList();
            for (Object result : results)
            {
               em.remove(result);
            }
         }
         
         em.remove(instance);
      }
      catch (NoResultException ex)
      {
         throw new IdentityException(String.format(
               "Exception removing identity object - [%s] not found.", 
               identity), ex);
      }
   }

   public void removeRelationship(IdentityStoreInvocationContext ctx,
         IdentityObject fromIdentity, IdentityObject toIdentity,
         IdentityObjectRelationshipType relationshipType,
         String relationshipName) throws IdentityException
   {
      Property<?> fromProperty = modelProperties.get(PROPERTY_RELATIONSHIP_FROM);
      Property<?> toProperty = modelProperties.get(PROPERTY_RELATIONSHIP_TO);
      Property<?> relationshipTypeProp = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);
      
      EntityManager em = getEntityManager(ctx);

      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(identityClass);
      Root<?> root = criteria.from(identityClass);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      predicates.add(builder.equal(root.get(fromProperty.getName()), 
            lookupIdentity(fromIdentity, em)));
      predicates.add(builder.equal(root.get(toProperty.getName()), 
            lookupIdentity(toIdentity, em)));
      predicates.add(builder.equal(root.get(relationshipTypeProp.getName()), 
            lookupRelationshipType(relationshipType, em)));
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      Object relationship = em.createQuery(criteria).getSingleResult();
      em.remove(relationship);
   }

   public String removeRelationshipName(IdentityStoreInvocationContext ctx,
         String name) throws IdentityException, OperationNotSupportedException
   {
      Property<?> nameProp = modelProperties.get(PROPERTY_ROLE_TYPE_NAME);
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(roleTypeClass);
      Root<?> root = criteria.from(roleTypeClass);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      predicates.add(builder.equal(root.get(nameProp.getName()), name));
      criteria.where(predicates.toArray((new Predicate[0])));
      Object roleType = em.createQuery(criteria).getSingleResult();
      em.remove(roleType);
      
      return null;
   }

   public void removeRelationshipNameProperties(
         IdentityStoreInvocationContext ctx, String name, Set<String> properties)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      System.out.println("*** Invoked unimplemented method removeRelationshipNameProperties()");
   }

   public void removeRelationshipProperties(IdentityStoreInvocationContext ctx,
         IdentityObjectRelationship relationship, Set<String> properties)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      System.out.println("*** Invoked unimplemented method removeRelationshipProperties()");
   }

   public void removeRelationships(
         IdentityStoreInvocationContext ctx,
         IdentityObject identity1, IdentityObject identity2, boolean named)
         throws IdentityException
   {
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(relationshipClass);
      Root<?> root = criteria.from(relationshipClass);
      
      Property<?> relationshipFromProp = modelProperties.get(PROPERTY_RELATIONSHIP_FROM);
      Property<?> relationshipToProp = modelProperties.get(PROPERTY_RELATIONSHIP_TO);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      
      if (identity1 != null)
      {
         predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
               lookupIdentity(identity1, em)));
      }
      
      if (identity2 != null)
      {
         predicates.add(builder.equal(root.get(relationshipToProp.getName()),
               lookupIdentity(identity2, em)));
      }
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      List<?> results = em.createQuery(criteria).getResultList();
      for (Object result : results)
      {
         em.remove(result);
      }
      
      criteria = builder.createQuery(relationshipClass);
      criteria.from(relationshipClass);
      
      predicates = new ArrayList<Predicate>();
      
      if (identity2 != null)
      {
         predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
               lookupIdentity(identity2, em)));
      }
      
      if (identity1 != null)
      {
         predicates.add(builder.equal(root.get(relationshipToProp.getName()),
               lookupIdentity(identity1, em)));
      }
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      results = em.createQuery(criteria).getResultList();
      for (Object result : results)
      {
         em.remove(result);
      }
   }

   public Set<IdentityObjectRelationship> resolveRelationships(
         IdentityStoreInvocationContext ctx,
         IdentityObject fromIdentity, IdentityObject toIdentity,
         IdentityObjectRelationshipType relationshipType)
         throws IdentityException
   {
      Set<IdentityObjectRelationship> relationships = new HashSet<IdentityObjectRelationship>();
      
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(relationshipClass);
      Root<?> root = criteria.from(relationshipClass);
      
      Property<?> relationshipFromProp = modelProperties.get(PROPERTY_RELATIONSHIP_FROM);
      Property<?> relationshipToProp = modelProperties.get(PROPERTY_RELATIONSHIP_TO);
      Property<?> relationshipTypeProp = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);
      Property<?> relationshipNameProp = modelProperties.get(PROPERTY_RELATIONSHIP_NAME);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      
      if (fromIdentity != null)
      {
         predicates.add(builder.equal(root.get(relationshipFromProp.getName()), 
            lookupIdentity(fromIdentity, em)));
      }
      
      if (toIdentity != null)
      {
         predicates.add(builder.equal(root.get(relationshipToProp.getName()),
            lookupIdentity(toIdentity, em)));
      }
      
      if (relationshipType != null)
      {
         predicates.add(builder.equal(root.get(relationshipTypeProp.getName()),
               lookupRelationshipType(relationshipType, em)));
      }
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      List<?> results = em.createQuery(criteria).getResultList();
      
      EntityToSpiConverter converter = new EntityToSpiConverter();
      
      for (Object result : results)
      {
         IdentityObjectRelationship relationship = new IdentityObjectRelationshipImpl(
               converter.convertToIdentityObject(relationshipFromProp.getValue(result)),
               converter.convertToIdentityObject(relationshipToProp.getValue(result)),
               (String) relationshipNameProp.getValue(result),
               converter.convertToRelationshipType(relationshipTypeProp.getValue(result))         
         );
         
         relationships.add(relationship);
      }
      
      return relationships;
   }

   public Set<IdentityObjectRelationship> resolveRelationships(
         IdentityStoreInvocationContext ctx, IdentityObject identity,
         IdentityObjectRelationshipType relationshipType, boolean parent,
         boolean named, String name) throws IdentityException
   {
      Set<IdentityObjectRelationship> relationships = new HashSet<IdentityObjectRelationship>();
      
      EntityManager em = getEntityManager(ctx);
      
      CriteriaBuilder builder = em.getCriteriaBuilder();
      CriteriaQuery<?> criteria = builder.createQuery(relationshipClass);
      Root<?> root = criteria.from(relationshipClass);
      
      Property<?> relationshipFromProp = modelProperties.get(PROPERTY_RELATIONSHIP_FROM);
      Property<?> relationshipToProp = modelProperties.get(PROPERTY_RELATIONSHIP_TO);
      Property<?> relationshipTypeProp = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);
      Property<?> relationshipNameProp = modelProperties.get(PROPERTY_RELATIONSHIP_NAME);
      
      List<Predicate> predicates = new ArrayList<Predicate>();
      
      if (parent)
      {
         predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
               lookupIdentity(identity, em)));
      }
      else
      {
         predicates.add(builder.equal(root.get(relationshipToProp.getName()), 
               lookupIdentity(identity, em)));
      }
            
      if (relationshipType != null)
      {
         predicates.add(builder.equal(root.get(relationshipTypeProp.getName()),
               lookupRelationshipType(relationshipType, em)));
      }
      
      if (named)
      {
         if (name != null)
         {
            predicates.add(builder.equal(root.get(relationshipNameProp.getName()),
               name));
         }
         else
         {
            predicates.add(builder.isNotNull(root.get(relationshipNameProp.getName())));
         }
      }
      
      criteria.where(predicates.toArray(new Predicate[0]));
      
      List<?> results = em.createQuery(criteria).getResultList();
      
      EntityToSpiConverter converter = new EntityToSpiConverter();
      
      for (Object result : results)
      {
         IdentityObjectRelationship relationship = new IdentityObjectRelationshipImpl(
               converter.convertToIdentityObject(relationshipFromProp.getValue(result)),
               converter.convertToIdentityObject(relationshipToProp.getValue(result)),
               (String) relationshipNameProp.getValue(result),
               converter.convertToRelationshipType(relationshipTypeProp.getValue(result))         
         );
         
         relationships.add(relationship);
      }
      
      return relationships;
   }

   public void setRelationshipNameProperties(
         IdentityStoreInvocationContext ctx, String name,
         Map<String, String> properties) throws IdentityException,
         OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      System.out.println("*** Invoked unimplemented method setRelationshipNameProperties()");
      
   }

   public void setRelationshipProperties(IdentityStoreInvocationContext ctx,
         IdentityObjectRelationship relationship, Map<String, String> properties)
         throws IdentityException, OperationNotSupportedException
   {
      // TODO Auto-generated method stub
      System.out.println("*** Invoked unimplemented method setRelationshipProperties()");
   }

   public void updateCredential(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, IdentityObjectCredential credential)
         throws IdentityException
   {
      EntityManager em = getEntityManager(ctx);
      
      Property<Object> credentialValue = modelProperties.get(PROPERTY_CREDENTIAL_VALUE);
      
      if (credentialClass != null)
      {
         Property<Object> credentialIdentity = modelProperties.get(PROPERTY_CREDENTIAL_IDENTITY);
         Property<Object> credentialType = modelProperties.get(PROPERTY_CREDENTIAL_TYPE);
         Object identity = lookupIdentity(identityObject, em);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(credentialClass);
         Root<?> root = criteria.from(credentialClass);
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(credentialIdentity.getName()),
               identity));
         
         if (credentialType != null)
         {
            if (String.class.equals(credentialType.getJavaClass()))
            {
               predicates.add(builder.equal(root.get(credentialType.getName()),
                     credential.getType().getName()));
            }
            else
            {
               predicates.add(builder.equal(root.get(credentialType.getName()),
                     lookupCredentialTypeEntity(credential.getType().getName(), em)));
            }
         }
         
         criteria.where(predicates.toArray(new Predicate[0]));
         
         List<?> results = em.createQuery(criteria).getResultList();
         
         if (results.isEmpty())
         {
            // The credential doesn't exist, let's create it
            try
            {
               Object newCredential = credentialClass.newInstance();
               credentialIdentity.setValue(newCredential, identity);
               credentialValue.setValue(newCredential, credential.getValue());
               credentialType.setValue(newCredential, 
                     lookupCredentialTypeEntity(credential.getType().getName(), em));
               
               em.persist(newCredential);
            }
            catch (IllegalAccessException ex)
            {
               throw new IdentityException("Error updating credential - could " +
                     "not create credential instance", ex);
            }
            catch (InstantiationException ex)
            {
               throw new IdentityException("Error updating credential - could " +
                     "not create credential instance", ex);
            }
         }
         else
         {
            // TODO there shouldn't be multiple credentials with the same type,
            // but if there are, we need to deal with it somehow.. for now just use the first one
            
            Object result = results.get(0);
            credentialValue.setValue(result, credential.getValue());
            
            em.merge(result);
         }
      }
      else
      {
         // The credential is stored in the identity class, update it there
         
         Property<Object> credentialProp = modelProperties.get(PROPERTY_CREDENTIAL_VALUE);
         Object identity = lookupIdentity(identityObject, em);
         
         credentialProp.setValue(identity, credential.getValue());
         
         em.merge(identity);         
      }

   }

   public boolean validateCredential(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, IdentityObjectCredential credential)
         throws IdentityException
   {
      EntityManager em = getEntityManager(ctx);

      Property<?> credentialValue = modelProperties.get(PROPERTY_CREDENTIAL_VALUE);
      
      // Either credentials are stored in their own class...
      if (credentialClass != null)
      {
         Property<?> credentialIdentity = modelProperties.get(PROPERTY_CREDENTIAL_IDENTITY);
         Property<?> credentialType = modelProperties.get(PROPERTY_CREDENTIAL_TYPE);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(credentialClass);
         Root<?> root = criteria.from(credentialClass);
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(credentialIdentity.getName()), 
               lookupIdentity(identityObject, em)));
         
         if (credentialType != null)
         {
            if (String.class.equals(credentialType.getJavaClass()))
            {
               predicates.add(builder.equal(root.get(credentialType.getName()),
                     credential.getType().getName()));
            }
            else
            {
               predicates.add(builder.equal(root.get(credentialType.getName()),
                     lookupCredentialTypeEntity(credential.getType().getName(), em)));
            }
         }
         
         criteria.where(predicates.toArray(new Predicate[0]));
         
         List<?> results = em.createQuery(criteria).getResultList();
         
         if (results.isEmpty()) return false;
         
         // TODO this only supports plain text passwords
         
         for (Object result : results)
         {
            Object val = credentialValue.getValue(result);
            if (val.equals(credential.getValue())) return true;
         }
      }
      // or they're stored in the identity class
      else
      {
         Property<?> identityNameProp = modelProperties.get(PROPERTY_IDENTITY_NAME);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(credentialValue.getDeclaringClass());
         
         Root<?> root = criteria.from(credentialValue.getDeclaringClass());
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(identityNameProp.getName()), 
               identityObject.getName()));
         
         criteria.where(predicates.toArray(new Predicate[0]));
         
         Object result = em.createQuery(criteria).getSingleResult();
         
         Object val = credentialValue.getValue(result);
         if (val.equals(credential.getValue())) return true;
      }

      return false;
   }

   public void addAttributes(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, IdentityObjectAttribute[] attributes)
         throws IdentityException
   {
      try
      {
         EntityManager em = getEntityManager(ctx);
         
         Object identity = lookupIdentity(identityObject, em);
         
         if (attributeClass != null)
         {
            Property<Object> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
            Property<Object> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
            Property<Object> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);
            
            for (IdentityObjectAttribute attrib : attributes)
            {
               if (attrib.getSize() == 1)
               {
                  Object attribute = attributeClass.newInstance();
                  attributeIdentityProp.setValue(attribute, identity);
                  attributeNameProp.setValue(attribute, attrib.getName());
                  attributeValueProp.setValue(attribute, attrib.getValue());
                  em.persist(attribute);
               }
               else
               {
                  for (Object value : attrib.getValues())
                  {
                     Object attribute = attributeClass.newInstance();
                     attributeIdentityProp.setValue(attribute, identity);
                     attributeNameProp.setValue(attribute, attrib.getName());
                     attributeValueProp.setValue(attribute, value);
                     em.persist(attribute);   
                  }
               }
            }
         }
      }
      catch (Exception e)
      {
         throw new IdentityException("Error while adding attributes.", e);
      }      
   }

   public IdentityObject findIdentityObjectByUniqueAttribute(
         IdentityStoreInvocationContext invocationCtx,
         IdentityObjectType identityObjectType,
         IdentityObjectAttribute attribute) throws IdentityException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public IdentityObjectAttribute getAttribute(IdentityStoreInvocationContext ctx,
         IdentityObject identity, String name) throws IdentityException
   {
      EntityManager em = getEntityManager(ctx);
      
      Property<?> attributeProperty = attributeProperties.get(name);
      if (attributeProperty != null)
      {
         // TODO implement attribute search for attributes scattered across the model
         
         
         return new SimpleAttribute(name);
      }
      else
      {
         // If there is no attributeClass set, we have nowhere else to look - return an empty attribute
         if (attributeClass == null) return new SimpleAttribute(name);
         
         Property<?> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
         Property<?> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
         Property<?> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
         Root<?> root = criteria.from(attributeClass);
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(attributeIdentityProp.getName()), 
               lookupIdentity(identity, em)));
         predicates.add(builder.equal(root.get(attributeNameProp.getName()),
               name));
         
         criteria.where(predicates.toArray(new Predicate[0]));
         
         List<?> results = em.createQuery(criteria).getResultList();
         
         if (results.size() == 0)
         {
            // No results found, return an empty attribute value
            return new SimpleAttribute(name);            
         }
         else if (results.size() == 1)
         {
            return new SimpleAttribute(name, attributeValueProp.getValue(results.get(0)));
         }
         else
         {
            Collection<Object> values = new ArrayList<Object>();
            for (Object result : results)
            {
               values.add(attributeValueProp.getValue(result));               
            }
            
            return new SimpleAttribute(name, values.toArray());
         }
      }
   }

   public Map<String, IdentityObjectAttribute> getAttributes(
         IdentityStoreInvocationContext ctx,
         IdentityObject identityObject) throws IdentityException
   {
      Map<String, IdentityObjectAttribute> attributes = new HashMap<String,IdentityObjectAttribute>();
      
      EntityManager em = getEntityManager(ctx);
      
      Object identity = lookupIdentity(identityObject, em);
      
      // TODO iterate through attributeProperties
      
      if (attributeClass != null)
      {
         Property<?> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
         Property<?> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
         Property<?> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
         Root<?> root = criteria.from(attributeClass);
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(attributeIdentityProp.getName()), 
               identity));
         
         criteria.where(predicates.toArray(new Predicate[0]));
         
         List<?> results = em.createQuery(criteria).getResultList();

         for (Object result : results)
         {
            String name = attributeNameProp.getValue(result).toString();
            Object value = attributeValueProp.getValue(result);
            
            if (attributes.containsKey(name))
            {
               IdentityObjectAttribute attr = attributes.get(name);
               attr.addValue(value);
            }
            else
            {
               attributes.put(name, new SimpleAttribute(name, value));
            }
         }
      }
      
      return attributes;
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

   public void removeAttributes(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, String[] attributeNames)
         throws IdentityException
   {      
      EntityManager em = getEntityManager(ctx);
      
      Object identity = lookupIdentity(identityObject, em);
            
      if (attributeClass != null)
      {
         Property<?> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
         Property<?> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
         
         CriteriaBuilder builder = em.getCriteriaBuilder();
         CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
         Root<?> root = criteria.from(attributeClass);
         
         List<Predicate> predicates = new ArrayList<Predicate>();
         predicates.add(builder.equal(root.get(attributeIdentityProp.getName()), 
               identity));
         
         criteria.where(predicates.toArray(new Predicate[0]));
         
         List<?> results = em.createQuery(criteria).getResultList();
         
         for (Object result : results)
         {
            String name = attributeNameProp.getValue(result).toString();
            for (String n : attributeNames)
            {
               if (name != null && name.equals(n))
               {
                  em.remove(result);
                  break;
               }
            }            
         }
      }
   }

   public void updateAttributes(IdentityStoreInvocationContext ctx,
         IdentityObject identityObject, IdentityObjectAttribute[] attributes)
         throws IdentityException
   {     
      try
      {
         EntityManager em = getEntityManager(ctx);
         
         Object identity = lookupIdentity(identityObject, em);
         
         if (attributeClass != null)
         {
            Property<Object> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
            Property<Object> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
            Property<Object> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);
            
            for (IdentityObjectAttribute attrib : attributes)
            {
               CriteriaBuilder builder = em.getCriteriaBuilder();
               CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
               Root<?> root = criteria.from(attributeClass);
               
               List<Predicate> predicates = new ArrayList<Predicate>();
               predicates.add(builder.equal(root.get(attributeIdentityProp.getName()), 
                     identity));
               predicates.add(builder.equal(root.get(attributeNameProp.getName()), 
                     attrib.getName()));
               
               criteria.where(predicates.toArray(new Predicate[0]));
               
               List<?> results = em.createQuery(criteria).getResultList();
      
               // All existing attribute values should be overwritten, so we
               // will first remove them, then add the new values
               
               if (!results.isEmpty())
               {
                  for (Object result : results)
                  {
                     em.remove(result);
                  }
               }
               
               for (Object value : attrib.getValues())
               {
                  Object attribute = attributeClass.newInstance();
                  attributeIdentityProp.setValue(attribute, identity);
                  attributeNameProp.setValue(attribute, attrib.getName());
                  attributeValueProp.setValue(attribute, value.toString());
                  em.persist(attribute);   
               }
            }
         }
      }
      catch (Exception e)
      {
         throw new IdentityException("Error while updating attributes.", e);
      }
   }

   public IdentityStoreSession createIdentityStoreSession()
         throws IdentityException
   {
      return createIdentityStoreSession(null);
   }
}
