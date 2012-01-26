package org.jboss.seam.security.management.picketlink;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.event.Event;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.NoResultException;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Path;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;
import org.jboss.seam.security.management.IdentityObjectRelationshipImpl;
import org.jboss.seam.security.management.IdentityObjectRelationshipTypeImpl;
import org.jboss.seam.security.management.IdentityObjectTypeImpl;
import org.jboss.solder.properties.Property;
import org.jboss.solder.properties.query.AnnotatedPropertyCriteria;
import org.jboss.solder.properties.query.NamedPropertyCriteria;
import org.jboss.solder.properties.query.PropertyCriteria;
import org.jboss.solder.properties.query.PropertyQueries;
import org.jboss.solder.properties.query.TypedPropertyCriteria;
import org.jboss.solder.reflection.Reflections;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.api.SimpleAttribute;
import org.picketlink.idm.impl.store.FeaturesMetaDataImpl;
import org.picketlink.idm.impl.types.SimpleIdentityObject;
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
public class JpaIdentityStore implements org.picketlink.idm.spi.store.IdentityStore, Serializable {
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
    private static final String PROPERTY_ATTRIBUTE_TYPE = "ATTRIBUTE_TYPE";

    private static final String ATTRIBUTE_TYPE_TEXT = "text";
    private static final String ATTRIBUTE_TYPE_BOOLEAN = "boolean";
    private static final String ATTRIBUTE_TYPE_DATE = "date";
    private static final String ATTRIBUTE_TYPE_INT = "int";
    private static final String ATTRIBUTE_TYPE_LONG = "long";
    private static final String ATTRIBUTE_TYPE_FLOAT = "float";
    private static final String ATTRIBUTE_TYPE_DOUBLE = "double";

    private class EntityToSpiConverter {
        private static final String IDENTITY_TYPE_CACHE_PREFIX = "identity_type:";
        private static final String RELATIONSHIP_TYPE_CACHE_PREFIX = "relationship_type:";

        private Map<Object, Object> cache = new HashMap<Object, Object>();

        private Property<?> identityIdProperty = modelProperties.get(PROPERTY_IDENTITY_ID);
        private Property<?> identityNameProperty = modelProperties.get(PROPERTY_IDENTITY_NAME);
        private Property<?> identityTypeProperty = modelProperties.get(PROPERTY_IDENTITY_TYPE);
        private Property<?> identityTypeNameProperty = modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME);
        private Property<?> relationshipTypeNameProperty = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME);

        public IdentityObject convertToIdentityObject(Object entity) {
            if (!identityClass.isAssignableFrom(entity.getClass())) {
                throw new IllegalArgumentException("Invalid identity entity");
            }

            if (cache.containsKey(entity)) {
                return (IdentityObject) cache.get(entity);
            } else {
                IdentityObject obj = new SimpleIdentityObject(
                        identityNameProperty.getValue(entity).toString(),
                        identityIdProperty.getValue(entity).toString(),                        
                        convertToIdentityObjectType(identityTypeProperty.getValue(entity)));
                cache.put(entity, obj);

                return obj;
            }
        }

        public IdentityObjectType convertToIdentityObjectType(Object value) {
            if (value instanceof String) {
                String key = IDENTITY_TYPE_CACHE_PREFIX + (String) value;
                if (cache.containsKey(key)) return (IdentityObjectType) cache.get(key);

                IdentityObjectType type = new IdentityObjectTypeImpl((String) value);
                cache.put(key, type);
                return type;
            } else {
                if (cache.containsKey(value)) return (IdentityObjectType) cache.get(value);
                IdentityObjectType type = new IdentityObjectTypeImpl(
                        (String) identityTypeNameProperty.getValue(value));
                cache.put(value, type);
                return type;
            }
        }

        public IdentityObjectRelationshipType convertToRelationshipType(Object value) {
            if (value instanceof String) {
                String key = RELATIONSHIP_TYPE_CACHE_PREFIX + (String) value;
                if (cache.containsKey(key)) return (IdentityObjectRelationshipType) cache.get(key);

                IdentityObjectRelationshipType type = new IdentityObjectRelationshipTypeImpl((String) value);
                cache.put(key, type);
                return type;
            } else {
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
    private Map<String, Property<Object>> modelProperties = new HashMap<String, Property<Object>>();

    /**
     * Used to map attributes to properties spread across the object model
     *
     */
    private class MappedAttribute {
        /**
         * The property of the IdentityObject class that references the object that
         * contains the attribute property
         */
        private Property<Object> identityProperty;

        /**
         * The property of the mapped object that contains the attribute value
         */
        private Property<Object> attributeProperty;

        public MappedAttribute(Property<Object> identityProperty, Property<Object> attributeProperty) {
            this.identityProperty = identityProperty;
            this.attributeProperty = attributeProperty;
        }

        public Property<Object> getIdentityProperty() {
            return identityProperty;
        }

        public Property<Object> getAttributeProperty() {
            return attributeProperty;
        }
    }

    /**
     * Attribute properties
     */
    private Map<String, MappedAttribute> attributeProperties = new HashMap<String, MappedAttribute>();

    boolean namedRelationshipsSupported = false;
    private FeaturesMetaData featuresMetaData;

    private class PropertyTypeCriteria implements PropertyCriteria {
        private PropertyType pt;

        public PropertyTypeCriteria(PropertyType pt) {
            this.pt = pt;
        }

        public boolean fieldMatches(Field f) {
            return f.isAnnotationPresent(IdentityProperty.class) &&
                    f.getAnnotation(IdentityProperty.class).value().equals(pt);
        }

        public boolean methodMatches(Method m) {
            return m.isAnnotationPresent(IdentityProperty.class) &&
                    m.getAnnotation(IdentityProperty.class).value().equals(pt);
        }
    }

    public JpaIdentityStore(String id) {
        this.id = id;
    }

    public void bootstrap(IdentityStoreConfigurationContext configurationContext)
            throws IdentityException {
        String clsName = configurationContext.getStoreConfigurationMetaData()
                .getOptionSingleValue(OPTION_IDENTITY_CLASS_NAME);

        if (clsName == null) {
            throw new IdentityException("Error bootstrapping JpaIdentityStore - identity entity class cannot be null");
        }

        try {
            identityClass = Reflections.classForName(clsName);
        } catch (ClassNotFoundException e) {
            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid identity entity class: " + clsName);
        }

        if (identityClass == null) {
            throw new IdentityException(
                    "Error initializing JpaIdentityStore - identityClass not set");
        }

        clsName = configurationContext.getStoreConfigurationMetaData()
                .getOptionSingleValue(OPTION_CREDENTIAL_CLASS_NAME);

        if (clsName != null) {
            try {
                credentialClass = Class.forName(clsName);
            } catch (ClassNotFoundException e) {
                throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid credential entity class: " + clsName);
            }
        }

        clsName = configurationContext.getStoreConfigurationMetaData()
                .getOptionSingleValue(OPTION_RELATIONSHIP_CLASS_NAME);

        try {
            relationshipClass = Class.forName(clsName);
        } catch (ClassNotFoundException e) {
            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid relationship entity class: " + clsName);
        }

        clsName = configurationContext.getStoreConfigurationMetaData()
                .getOptionSingleValue(OPTION_ROLE_TYPE_CLASS_NAME);

        if (clsName != null) {
            try {
                roleTypeClass = Class.forName(clsName);
                namedRelationshipsSupported = true;
            } catch (ClassNotFoundException e) {
                throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid role type entity class: " + clsName);
            }
        }

        clsName = configurationContext.getStoreConfigurationMetaData()
                .getOptionSingleValue(OPTION_ATTRIBUTE_CLASS_NAME);
        if (clsName != null) {
            try {
                attributeClass = Class.forName(clsName);
            } catch (ClassNotFoundException e) {
                throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid attribute entity class: " + clsName);
            }
        }

        configureIdentityId();
        configureIdentityName();
        configureIdentityType();

        configureCredentials();
        configureRelationships();
        configureAttributes();

        if (namedRelationshipsSupported) {
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

    protected void configureIdentityId() throws IdentityException {
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
                .addCriteria(new AnnotatedPropertyCriteria(Id.class))
                .getResultList();

        if (props.size() == 1) {
            modelProperties.put(PROPERTY_IDENTITY_ID, props.get(0));
        } else {
            throw new IdentityException("Error initializing JpaIdentityStore - no Identity ID found.");
        }
    }

    protected void configureIdentityName() throws IdentityException {
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
                .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
                .getResultList();

        if (props.size() == 1) {
            modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                    "Ambiguous identity name property in identity class " + identityClass.getName());
        } else {
            Property<Object> p = findNamedProperty(identityClass, "username", "userName", "name");
            if (p != null) {
                modelProperties.put(PROPERTY_IDENTITY_NAME, p);
            } else {
                // Last resort - check whether the entity class exposes a single String property
                // if so, let's assume it's the identity name
                props = PropertyQueries.createQuery(identityClass)
                        .addCriteria(new TypedPropertyCriteria(String.class))
                        .getResultList();
                if (props.size() == 1) {
                    modelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
                }
            }
        }

        if (!modelProperties.containsKey(PROPERTY_IDENTITY_NAME)) {
            throw new IdentityException("Error initializing JpaIdentityStore - no valid identity name property found.");
        }
    }

    protected void configureIdentityType() throws IdentityException {
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
                .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
                .getResultList();

        if (props.size() == 1) {
            modelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                    "Ambiguous identity type property in identity class " + identityClass.getName());
        } else {
            Property<Object> p = findNamedProperty(identityClass, "identityObjectType",
                    "identityType", "identityObjectTypeName", "identityTypeName",
                    "typeName", "discriminator", "accountType", "userType", "type");
            if (p != null) {
                modelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
            } else {
                // Last resort - let's check all properties, and try to find one
                // with an entity type that has "type" in its name
                props = PropertyQueries.createQuery(identityClass).getResultList();
                search:
                for (Property<Object> typeProp : props) {
                    if (typeProp.getJavaClass().isAnnotationPresent(Entity.class) &&
                            (typeProp.getJavaClass().getSimpleName().contains("type") ||
                                    typeProp.getJavaClass().getSimpleName().contains("Type"))) {
                        // we have a potential match, let's check if this entity has a name property
                        Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                                "identityObjectTypeName", "identityTypeName", "typeName", "name");
                        if (nameProp != null) {
                            modelProperties.put(PROPERTY_IDENTITY_TYPE, typeProp);
                            modelProperties.put(PROPERTY_IDENTITY_TYPE_NAME, nameProp);
                            break search;
                        }
                    }
                }
            }
        }

        Property<?> typeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);

        if (typeProp == null) {
            throw new IdentityException("Error initializing JpaIdentityStore - no valid identity type property found.");
        }

        if (!String.class.equals(typeProp.getJavaClass()) &&
                !modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME)) {
            // We're not dealing with a simple type name - validate the lookup type
            Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                    "identityObjectTypeName", "identityTypeName", "typeName", "name");
            if (nameProp != null) {
                modelProperties.put(PROPERTY_IDENTITY_TYPE_NAME, nameProp);
            } else {
                throw new IdentityException("Error initializing JpaIdentityStore - no valid identity type name property found.");
            }
        }
    }

    protected Property<Object> findNamedProperty(Class<?> targetClass, String... allowedNames) {
        List<Property<Object>> props = PropertyQueries.createQuery(targetClass)
                .addCriteria(new TypedPropertyCriteria(String.class))
                .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
                .getResultList();

        if (props.size() == 1) {
            return props.get(0);
        } else {
            props = PropertyQueries.createQuery(targetClass)
                    .addCriteria(new TypedPropertyCriteria(String.class))
                    .addCriteria(new NamedPropertyCriteria(allowedNames))
                    .getResultList();

            for (String name : allowedNames) {
                for (Property<Object> prop : props) {
                    if (name.equals(prop.getName())) return prop;
                }
            }
        }

        return null;
    }

    protected void configureCredentials() throws IdentityException {
        // If a credential entity has been explicitly configured, scan it
        if (credentialClass != null) {
            List<Property<Object>> props = PropertyQueries.createQuery(credentialClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.VALUE))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous credential value property in credential class " +
                                credentialClass.getName());
            } else {
                // Try scanning for a credential property also
                props = PropertyQueries.createQuery(credentialClass)
                        .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL))
                        .getResultList();
                if (props.size() == 1) {
                    modelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
                } else if (props.size() > 1) {
                    throw new IdentityException(
                            "Ambiguous credential value property in credential class " +
                                    credentialClass.getName());
                } else {
                    Property<Object> p = findNamedProperty(credentialClass, "credentialValue",
                            "password", "passwordHash", "credential", "value");
                    if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
                }
            }

            // Scan for the credential identity property
            props = PropertyQueries.createQuery(credentialClass)
                    .addCriteria(new TypedPropertyCriteria(identityClass))
                    .getResultList();
            if (props.size() == 1) {
                modelProperties.put(PROPERTY_CREDENTIAL_IDENTITY, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous identity property in credential class " +
                                credentialClass.getName());
            } else {
                // Scan for a named identity property
                props = PropertyQueries.createQuery(credentialClass)
                        .addCriteria(new NamedPropertyCriteria("identity", "identityObject"))
                        .getResultList();
                if (!props.isEmpty()) {
                    modelProperties.put(PROPERTY_CREDENTIAL_IDENTITY, props.get(0));
                } else {
                    throw new IdentityException("Error initializing JpaIdentityStore - no credential identity property found.");
                }
            }
        } else {
            // The credentials may be stored in the identity class
            List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous credential property in identity class " +
                                identityClass.getName());
            } else {
                Property<Object> p = findNamedProperty(identityClass, "credentialValue",
                        "password", "passwordHash", "credential", "value");
                if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
            }

            // If Credential is on Identity, it's see if Credential Type is too
            props = PropertyQueries.createQuery(identityClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL_TYPE))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous credential type property in identity class " +
                                identityClass.getName());
            } else {
                Property<Object> p = findNamedProperty(identityClass, "credentialType",
                        "identityObjectCredentialType", "type");
                if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_TYPE, p);
            }
        }

        if (!modelProperties.containsKey(PROPERTY_CREDENTIAL_VALUE)) {
            throw new IdentityException("Error initializing JpaIdentityStore - no credential value property found.");
        }

        // Scan for a credential type property
        if (modelProperties.get(PROPERTY_CREDENTIAL_TYPE) == null) { // We may have found it on identity
            List<Property<Object>> props = PropertyQueries.createQuery(credentialClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous credential type property in credential class " +
                                credentialClass.getName());
            } else {
                props = PropertyQueries.createQuery(credentialClass)
                        .addCriteria(new PropertyTypeCriteria(PropertyType.CREDENTIAL_TYPE))
                        .getResultList();

                if (props.size() == 1) {
                    modelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
                } else if (props.size() > 1) {
                    throw new IdentityException(
                            "Ambiguous credential type property in credential class " +
                                    credentialClass.getName());
                } else {
                    Property<Object> p = findNamedProperty(credentialClass, "credentialType",
                            "identityObjectCredentialType", "type");
                    if (p != null) modelProperties.put(PROPERTY_CREDENTIAL_TYPE, p);
                }
            }
        }

        Property<?> typeProp = modelProperties.get(PROPERTY_CREDENTIAL_TYPE);

        // If the credential type property isn't a String, then validate the lookup type
        if (!String.class.equals(typeProp.getJavaClass())) {
            Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                    "credentialObjectTypeName", "credentialTypeName", "typeName", "name");
            if (nameProp != null) {
                modelProperties.put(PROPERTY_CREDENTIAL_TYPE_NAME, nameProp);
            } else {
                throw new IdentityException("Error initializing JpaIdentityStore - no valid credential type name property found.");
            }
        }
    }

    protected void configureRelationships() throws IdentityException {
        if (relationshipClass == null) {
            throw new IdentityException("Error initializing JpaIdentityStore - relationshipClass not set.");
        }

        List<Property<Object>> props = PropertyQueries.createQuery(relationshipClass)
                .addCriteria(new TypedPropertyCriteria(identityClass))
                .addCriteria(new PropertyTypeCriteria(PropertyType.RELATIONSHIP_FROM))
                .getResultList();

        if (props.size() == 1) {
            modelProperties.put(PROPERTY_RELATIONSHIP_FROM, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                    "Ambiguous relationshipFrom property in relationship class " +
                            relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass, "relationshipFrom",
                    "fromIdentityObject", "fromIdentity");
            if (p != null) {
                modelProperties.put(PROPERTY_RELATIONSHIP_FROM, p);
            } else {
                // Last resort - search for a property with a type of identityClass
                // and a "from" in its name
                props = PropertyQueries.createQuery(relationshipClass)
                        .addCriteria(new TypedPropertyCriteria(identityClass))
                        .getResultList();

                for (Property<Object> prop : props) {
                    if (prop.getName().contains("from")) {
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

        if (props.size() == 1) {
            modelProperties.put(PROPERTY_RELATIONSHIP_TO, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                    "Ambiguous relationshipTo property in relationship class " +
                            relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass, "relationshipTo",
                    "toIdentityObject", "toIdentity");
            if (p != null) {
                modelProperties.put(PROPERTY_RELATIONSHIP_TO, p);
            } else {
                // Last resort - search for a property with a type of identityClass
                // and a "to" in its name
                props = PropertyQueries.createQuery(relationshipClass)
                        .addCriteria(new TypedPropertyCriteria(identityClass))
                        .getResultList();

                for (Property<Object> prop : props) {
                    if (prop.getName().contains("to")) {
                        modelProperties.put(PROPERTY_RELATIONSHIP_TO, prop);
                        break;
                    }
                }
            }
        }

        props = PropertyQueries.createQuery(relationshipClass)
                .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
                .getResultList();
        if (props.size() == 1) {
            modelProperties.put(PROPERTY_RELATIONSHIP_TYPE, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                    "Ambiguous relationshipType property in relationship class " +
                            relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass,
                    "identityRelationshipType", "relationshipType", "type");
            if (p != null) {
                modelProperties.put(PROPERTY_RELATIONSHIP_TYPE, p);
            } else {
                props = PropertyQueries.createQuery(relationshipClass)
                        .getResultList();
                for (Property<Object> prop : props) {
                    if (prop.getName().contains("type")) {
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

        if (props.size() == 1) {
            modelProperties.put(PROPERTY_RELATIONSHIP_NAME, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                    "Ambiguous relationship name property in relationship class " +
                            relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass, "relationshipName", "name");
            if (p != null) {
                modelProperties.put(PROPERTY_RELATIONSHIP_NAME, p);
            }
        }

        if (modelProperties.containsKey(PROPERTY_RELATIONSHIP_NAME)) {
            namedRelationshipsSupported = true;
        }

        if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_FROM)) {
            throw new IdentityException(
                    "Error initializing JpaIdentityStore - no valid relationship from property found.");
        }

        if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TO)) {
            throw new IdentityException(
                    "Error initializing JpaIdentityStore - no valid relationship to property found.");
        }

        if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE)) {
            throw new IdentityException(
                    "Error initializing JpaIdentityStore - no valid relationship type property found.");
        }

        if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_NAME)) {
            throw new IdentityException(
                    "Error initializing JpaIdentityStore - no valid relationship name property found.");
        }

        Class<?> typeClass = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getJavaClass();
        if (!String.class.equals(typeClass)) {
            props = PropertyQueries.createQuery(typeClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
                    .addCriteria(new TypedPropertyCriteria(String.class))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_RELATIONSHIP_TYPE_NAME, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous relationship type name property in class " +
                                typeClass.getName());
            } else {
                Property<Object> p = findNamedProperty(typeClass, "relationshipTypeName",
                        "typeName", "name");
                if (p != null) {
                    modelProperties.put(PROPERTY_RELATIONSHIP_TYPE_NAME, p);
                }
            }

            if (!modelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE_NAME)) {
                throw new IdentityException(
                        "Error initializing JpaIdentityStore - no valid relationship type name property found");
            }
        }
    }

    protected void configureAttributes() throws IdentityException {
        // If an attribute class has been configured, scan it for attributes
        if (attributeClass != null) {
            List<Property<Object>> props = PropertyQueries.createQuery(attributeClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.NAME))
                    .addCriteria(new TypedPropertyCriteria(String.class))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_ATTRIBUTE_NAME, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous attribute name property in class " +
                                attributeClass.getName());
            } else {
                Property<Object> prop = findNamedProperty(attributeClass,
                        "attributeName", "name");
                if (prop != null) modelProperties.put(PROPERTY_ATTRIBUTE_NAME, prop);
            }

            props = PropertyQueries.createQuery(attributeClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.VALUE))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_ATTRIBUTE_VALUE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous attribute value property in class " +
                                attributeClass.getName());
            } else {
                Property<Object> prop = findNamedProperty(attributeClass,
                        "attributeValue", "value");
                if (prop != null) modelProperties.put(PROPERTY_ATTRIBUTE_VALUE, prop);
            }

            props = PropertyQueries.createQuery(attributeClass)
                    .addCriteria(new TypedPropertyCriteria(identityClass))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_ATTRIBUTE_IDENTITY, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous identity property in attribute class " +
                                attributeClass.getName());
            } else {
                throw new IdentityException("Error initializing JpaIdentityStore - " +
                        "no attribute identity property found.");
            }

            props = PropertyQueries.createQuery(attributeClass)
                    .addCriteria(new PropertyTypeCriteria(PropertyType.TYPE))
                    .getResultList();

            if (props.size() == 1) {
                modelProperties.put(PROPERTY_ATTRIBUTE_TYPE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                        "Ambiguous attribute type property in class " +
                                attributeClass.getName());
            }
        }

        // Scan for additional attributes in the identity class also
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass)
                .addCriteria(new PropertyTypeCriteria(PropertyType.ATTRIBUTE))
                .getResultList();

        for (Property<Object> p : props) {
            String attribName = p.getAnnotatedElement().getAnnotation(IdentityProperty.class).attributeName();

            if (attributeProperties.containsKey(attribName)) {
                Property<Object> other = attributeProperties.get(attribName).getAttributeProperty();

                throw new IdentityException("Multiple properties defined for attribute [" + attribName + "] - " +
                   "Property: " + other.getDeclaringClass().getName() + "." + other.getAnnotatedElement().toString() +
                   ", Property: " + p.getDeclaringClass().getName() + "." + p.getAnnotatedElement().toString());
            }

            attributeProperties.put(attribName, new MappedAttribute(null, p));
        }

        // scan any entity classes referenced by the identity class also
        props = PropertyQueries.createQuery(identityClass).getResultList();

        for (Property<Object> p : props) {
            if (!p.isReadOnly() && p.getJavaClass().isAnnotationPresent(Entity.class)) {
                List<Property<Object>> pp = PropertyQueries.createQuery(p.getJavaClass())
                        .addCriteria(new PropertyTypeCriteria(PropertyType.ATTRIBUTE))
                        .getResultList();

                for (Property<Object> attributeProperty : pp) {
                    String attribName = attributeProperty.getAnnotatedElement().getAnnotation(IdentityProperty.class).attributeName();

                    if (attributeProperties.containsKey(attribName)) {
                        Property<Object> other = attributeProperties.get(attribName).getAttributeProperty();

                        throw new IdentityException("Multiple properties defined for attribute [" + attribName + "] - " +
                           "Property: " + other.getDeclaringClass().getName() + "." + other.getAnnotatedElement().toString() +
                           ", Property: " + attributeProperty.getDeclaringClass().getName() + "." + attributeProperty.getAnnotatedElement().toString());
                    }

                    attributeProperties.put(attribName, new MappedAttribute(p, attributeProperty));
                }
            }
        }
    }

    protected void configureRoleTypeName() {
        Property<Object> relationshipNameProp = findNamedProperty(roleTypeClass, "name");
        if (relationshipNameProp != null) {
            modelProperties.put(PROPERTY_ROLE_TYPE_NAME, relationshipNameProp);
        }
    }

    protected class AttributeValue {
        private String encoded;
        private String type;

        public AttributeValue(String encoded, String type) {
            this.encoded = encoded;
            this.type = type;
        }

        public String getEncoded() {
            return encoded;
        }

        public String getType() {
            return type;
        }
    }

    public String getUserIdentityType() {
        return userIdentityType;
    }

    public void setUserIdentityType(String userIdentityType) {
        this.userIdentityType = userIdentityType;
    }

    public String getRoleIdentityType() {
        return roleIdentityType;
    }

    public void setRoleIdentityType(String roleIdentityType) {
        this.roleIdentityType = roleIdentityType;
    }

    public String getGroupIdentityType() {
        return groupIdentityType;
    }

    public void setGroupIdentityType(String groupIdentityType) {
        this.groupIdentityType = groupIdentityType;
    }

    public String getRelationshipTypeMembership() {
        return relationshipTypeMembership;
    }

    public void setRelationshipTypeMembership(String relationshipTypeMembership) {
        this.relationshipTypeMembership = relationshipTypeMembership;
    }

    public String getRelationshipTypeRole() {
        return relationshipTypeRole;
    }

    public void setRelationshipTypeRole(String relationshipTypeRole) {
        this.relationshipTypeRole = relationshipTypeRole;
    }

    @SuppressWarnings("unchecked")
    public IdentityStoreSession createIdentityStoreSession(
            Map<String, Object> sessionOptions) throws IdentityException {
        EntityManager em = (EntityManager) sessionOptions.get(IdentitySessionProducer.SESSION_OPTION_ENTITY_MANAGER);
        Event<IdentityObjectCreatedEvent> event = (Event<IdentityObjectCreatedEvent>) sessionOptions.get(IdentitySessionProducer.SESSION_OPTION_IDENTITY_OBJECT_CREATED_EVENT);

        return new JpaIdentityStoreSessionImpl(em, event);
    }

    public IdentityObject createIdentityObject(
            IdentityStoreInvocationContext invocationCtx, String name,
            IdentityObjectType identityObjectType) throws IdentityException {
        return createIdentityObject(invocationCtx, name, identityObjectType, null);
    }

    protected Object lookupIdentityType(String identityType, EntityManager em) {
        Property<Object> typeNameProp = modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME);

        try {
            // If there is no identity type table, just return the name
            if (typeNameProp == null) return identityType;

            final String identTypeEntityAnnotationValue = typeNameProp.getDeclaringClass().getAnnotation(Entity.class).name();
            final String identTypeEntityName = ("".equals(identTypeEntityAnnotationValue) ? typeNameProp.getDeclaringClass().getSimpleName() : identTypeEntityAnnotationValue);

            Object val = em.createQuery(
                    "select t from " + identTypeEntityName +
                            " t where t." + typeNameProp.getName() +
                            " = :identityType")
                    .setParameter("identityType", identityType)
                    .getSingleResult();
            return val;
        } catch (NoResultException ex) {
            try {
                // The identity type wasn't found, so create it
                Object instance = typeNameProp.getDeclaringClass().newInstance();
                typeNameProp.setValue(instance, identityType);
                em.persist(instance);
                return instance;
            } catch (Exception ex2) {
                throw new RuntimeException("Error creating identity type", ex2);
            }
        }
    }

    public IdentityObject createIdentityObject(
            IdentityStoreInvocationContext ctx, String name,
            IdentityObjectType identityObjectType, Map<String, String[]> attributes)
            throws IdentityException {
        try {
            Object identityInstance = identityClass.newInstance();
            modelProperties.get(PROPERTY_IDENTITY_NAME).setValue(identityInstance, name);

            Property<Object> typeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);

            if (String.class.equals(typeProp.getJavaClass())) {
                typeProp.setValue(identityInstance, identityObjectType.getName());
            } else {
                typeProp.setValue(identityInstance, lookupIdentityType(identityObjectType.getName(),
                        getEntityManager(ctx)));
            }

            EntityManager em = getEntityManager(ctx);

            for (String attribName : attributeProperties.keySet()) {
                MappedAttribute attrib = attributeProperties.get(attribName);
                if (attrib.getIdentityProperty() != null && attrib.getIdentityProperty().getValue(identityInstance) == null) {
                    Object instance = attrib.getIdentityProperty().getJavaClass().newInstance();
                    attrib.getIdentityProperty().setValue(identityInstance, instance);

                    em.persist(instance);
                }
            }

            em.persist(identityInstance);

            // Fire an event that contains the new identity object
            Event<IdentityObjectCreatedEvent> event = ((JpaIdentityStoreSessionImpl) ctx.getIdentityStoreSession()).getIdentityObjectCreatedEvent();

            if (event != null) {
                event.fire(new IdentityObjectCreatedEvent(identityInstance));
            }

            Object id = modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identityInstance);
            IdentityObject obj = new SimpleIdentityObject(name, (id != null ? id.toString() : null),
                    identityObjectType);

            if (attributes != null) {
                List<IdentityObjectAttribute> attribs = new ArrayList<IdentityObjectAttribute>();
                for (String key : attributes.keySet()) {
                    for (String value : attributes.get(key)) {
                        attribs.add(new SimpleAttribute(key, value));
                    }
                }

                updateAttributes(ctx, obj, attribs.toArray(new IdentityObjectAttribute[attribs.size()]));
            }

            em.flush();

            return obj;
        } catch (Exception ex) {
            throw new IdentityException("Error creating identity object", ex);
        }
    }

    public IdentityObjectRelationship createRelationship(
            IdentityStoreInvocationContext invocationCtx,
            IdentityObject fromIdentity, IdentityObject toIdentity,
            IdentityObjectRelationshipType relationshipType,
            String relationshipName, boolean createNames) throws IdentityException {
        try {
            EntityManager em = getEntityManager(invocationCtx);

            Object relationship = relationshipClass.newInstance();

            modelProperties.get(PROPERTY_RELATIONSHIP_FROM).setValue(relationship,
                    lookupIdentity(fromIdentity, em));
            modelProperties.get(PROPERTY_RELATIONSHIP_TO).setValue(relationship,
                    lookupIdentity(toIdentity, em));

            Property<Object> type = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);
            if (String.class.equals(modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getJavaClass())) {
                type.setValue(relationship, relationshipType.getName());
            } else {
                type.setValue(relationship, lookupRelationshipType(relationshipType, em));
            }

            modelProperties.get(PROPERTY_RELATIONSHIP_NAME).setValue(relationship,
                    relationshipName);

            em.persist(relationship);
            em.flush();

            return new IdentityObjectRelationshipImpl(fromIdentity, toIdentity,
                    relationshipName, relationshipType);
        } catch (Exception ex) {
            throw new IdentityException("Exception creating relationship", ex);
        }
    }

    protected Object lookupIdentity(IdentityObject obj, EntityManager em) {
        Property<?> identityNameProp = modelProperties.get(PROPERTY_IDENTITY_NAME);
        Property<?> identityTypeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);

        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<?> criteria = builder.createQuery(identityClass);
        Root<?> root = criteria.from(identityClass);

        List<Predicate> predicates = new ArrayList<Predicate>();
        predicates.add(builder.equal(root.get(identityNameProp.getName()), obj.getName()));
        predicates.add(builder.equal(root.get(identityTypeProp.getName()), lookupIdentityType(obj.getIdentityType().getName(), em)));

        // TODO add criteria for identity type

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        return em.createQuery(criteria).getSingleResult();
    }

    protected Object lookupCredentialTypeEntity(String name, EntityManager em) {
        Property<?> credentialTypeNameProp = modelProperties.get(PROPERTY_CREDENTIAL_TYPE_NAME);

        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<?> criteria = builder.createQuery(credentialTypeNameProp.getDeclaringClass());
        Root<?> root = criteria.from(credentialTypeNameProp.getDeclaringClass());

        List<Predicate> predicates = new ArrayList<Predicate>();
        predicates.add(builder.equal(root.get(credentialTypeNameProp.getName()), name));
        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        return em.createQuery(criteria).getSingleResult();
    }

    protected Object lookupRelationshipType(IdentityObjectRelationshipType relationshipType, EntityManager em) {
        Property<?> relationshipTypeNameProp = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME);

        if (relationshipTypeNameProp != null) {
            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(relationshipTypeNameProp.getDeclaringClass());
            Root<?> root = criteria.from(relationshipTypeNameProp.getDeclaringClass());

            List<Predicate> predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(relationshipTypeNameProp.getName()), relationshipType.getName()));
            criteria.where(predicates.toArray(new Predicate[predicates.size()]));

            return em.createQuery(criteria).getSingleResult();
        } else {
            return relationshipType.getName();
        }
    }

    public String createRelationshipName(IdentityStoreInvocationContext ctx,
                                         String name) throws IdentityException, OperationNotSupportedException {
        try {
            Property<Object> roleTypeNameProp = modelProperties.get(PROPERTY_ROLE_TYPE_NAME);

            Object roleTypeInstance = roleTypeClass.newInstance();
            roleTypeNameProp.setValue(roleTypeInstance, name);

            EntityManager em = getEntityManager(ctx);

            em.persist(roleTypeInstance);
            em.flush();
            return name;
        } catch (Exception ex) {
            throw new IdentityException("Error creating relationship name", ex);
        }
    }

    public EntityManager getEntityManager(IdentityStoreInvocationContext invocationContext) {
        return ((JpaIdentityStoreSessionImpl) invocationContext.getIdentityStoreSession()).getEntityManager();
    }

    public IdentityObject findIdentityObject(IdentityStoreInvocationContext invocationContext, String id)
            throws IdentityException {
        try {
            final String identEntityAnnotationValue = identityClass.getAnnotation(Entity.class).name();
            final String identEntityName = ("".equals(identEntityAnnotationValue) ? identityClass.getSimpleName() : identEntityAnnotationValue);

            Object identity = getEntityManager(invocationContext).createQuery("select i from " +
                    identEntityName + " i where i." +
                    modelProperties.get(PROPERTY_IDENTITY_ID).getName() +
                    " = :id")
                    .setParameter("id", id)
                    .getSingleResult();

            IdentityObjectType type = modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME) ?
                    new IdentityObjectTypeImpl(
                            modelProperties.get(PROPERTY_IDENTITY_TYPE_NAME).getValue(
                                    modelProperties.get(PROPERTY_IDENTITY_TYPE).getValue(identity)).toString()) :
                    new IdentityObjectTypeImpl(modelProperties.get(PROPERTY_IDENTITY_TYPE).getValue(identity).toString());


            return new SimpleIdentityObject(                    
                    modelProperties.get(PROPERTY_IDENTITY_NAME).getValue(identity).toString(),
                    modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identity).toString(),
                    type);
        } catch (NoResultException ex) {
            return null;
        }
    }

    public IdentityObject findIdentityObject(
            IdentityStoreInvocationContext invocationContext, String name,
            IdentityObjectType identityObjectType) throws IdentityException {
        try {
            Object identityType = modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME) ?
                    lookupIdentityType(identityObjectType.getName(), getEntityManager(invocationContext)) :
                    identityObjectType.getName();

            final String identEntityAnnotationValue = identityClass.getAnnotation(Entity.class).name();
            final String identEntityName = ("".equals(identEntityAnnotationValue) ? identityClass.getSimpleName() : identEntityAnnotationValue);

            Object identity = getEntityManager(invocationContext).createQuery("select i from " +
                    identEntityName + " i where i." +
                    modelProperties.get(PROPERTY_IDENTITY_NAME).getName() +
                    " = :name and i." + modelProperties.get(PROPERTY_IDENTITY_TYPE).getName() +
                    " = :type")
                    .setParameter("name", name)
                    .setParameter("type", identityType)
                    .getSingleResult();

            return new SimpleIdentityObject(
                    modelProperties.get(PROPERTY_IDENTITY_NAME).getValue(identity).toString(),
                    modelProperties.get(PROPERTY_IDENTITY_ID).getValue(identity).toString(),                    
                    identityObjectType);
        } catch (NoResultException ex) {
            return null;
        }
    }

    public Collection<IdentityObject> findIdentityObject(
            IdentityStoreInvocationContext ctx,
            IdentityObjectType identityType, IdentityObjectSearchCriteria searchCriteria)
            throws IdentityException {
        List<IdentityObject> objs = new ArrayList<IdentityObject>();

        EntityManager em = getEntityManager(ctx);

        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<?> criteria = builder.createQuery(identityClass);

        Root<?> root = criteria.from(identityClass);

        Property<?> identityTypeProp = modelProperties.get(PROPERTY_IDENTITY_TYPE);

        List<Predicate> predicates = new ArrayList<Predicate>();

        if (identityType != null) {
            predicates.add(builder.equal(root.get(identityTypeProp.getName()),
                    lookupIdentityType(identityType.getName(), em)));
        }

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        List<?> results = em.createQuery(criteria).getResultList();

        EntityToSpiConverter converter = new EntityToSpiConverter();

        for (Object result : results) {
            objs.add(converter.convertToIdentityObject(result));
        }

        return objs;
    }

    public String getId() {
        return id;
    }

    public Set<String> getRelationshipNames(IdentityStoreInvocationContext ctx,
                                            IdentityObjectSearchCriteria searchCriteria) throws IdentityException,
            OperationNotSupportedException {
        Set<String> names = new HashSet<String>();

        if (!featuresMetaData.isNamedRelationshipsSupported()) return names;

        Property<Object> roleTypeNameProp = modelProperties.get(PROPERTY_ROLE_TYPE_NAME);

        if (roleTypeClass != null) {
            EntityManager em = getEntityManager(ctx);

            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(roleTypeClass);
            criteria.from(roleTypeClass);

            List<?> results = em.createQuery(criteria).getResultList();

            for (Object result : results) {
                names.add(roleTypeNameProp.getValue(result).toString());
            }
        }

        return names;
    }

    public Set<String> getRelationshipNames(IdentityStoreInvocationContext ctx,
                                            IdentityObject identity, IdentityObjectSearchCriteria searchCriteria)
            throws IdentityException, OperationNotSupportedException {
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

        Path<String> rolesOnly = root.get(relationshipNameProperty.getName());
        predicates.add(builder.like(rolesOnly, "%"));

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        List<?> results = em.createQuery(criteria).getResultList();
        for (Object result : results) {
            names.add((String) relationshipNameProperty.getValue(result));
        }

        return names;
    }

    public Map<String, String> getRelationshipProperties(
            IdentityStoreInvocationContext ctx,
            IdentityObjectRelationship relationship) throws IdentityException,
            OperationNotSupportedException {
        throw new OperationNotSupportedException("getRelationshipProperties() not supported");
    }

    public FeaturesMetaData getSupportedFeatures() {
        return featuresMetaData;
    }

    public void removeIdentityObject(
            IdentityStoreInvocationContext ctx, IdentityObject identity)
            throws IdentityException {
        removeRelationships(ctx, identity, null, false);

        EntityManager em = getEntityManager(ctx);

        Property<?> nameProperty = modelProperties.get(PROPERTY_IDENTITY_NAME);
        Property<?> typeProperty = modelProperties.get(PROPERTY_IDENTITY_TYPE);

        CriteriaBuilder builder = em.getCriteriaBuilder();

        CriteriaQuery<?> criteria = builder.createQuery(identityClass);
        Root<?> root = criteria.from(identityClass);

        List<Predicate> predicates = new ArrayList<Predicate>();
        predicates.add(builder.equal(root.get(nameProperty.getName()),
                identity.getName()));
        predicates.add(builder.equal(root.get(typeProperty.getName()),
                lookupIdentityType(identity.getIdentityType().getName(), em)));

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        try {
            Object instance = em.createQuery(criteria).getSingleResult();

            // If there is a credential class, delete any credentials
            if (credentialClass != null) {
                Property<?> credentialIdentityProp = modelProperties.get(PROPERTY_CREDENTIAL_IDENTITY);

                criteria = builder.createQuery(credentialClass);
                root = criteria.from(credentialClass);

                predicates = new ArrayList<Predicate>();
                predicates.add(builder.equal(root.get(credentialIdentityProp.getName()),
                        instance));
                criteria.where(predicates.toArray(new Predicate[predicates.size()]));

                List<?> results = em.createQuery(criteria).getResultList();
                for (Object result : results) {
                    em.remove(result);
                }
            }

            // If there is an attribute class, delete any attributes
            if (attributeClass != null) {
                Property<?> attributeIdentityProperty = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
                criteria = builder.createQuery(attributeClass);
                root = criteria.from(attributeClass);

                predicates = new ArrayList<Predicate>();
                predicates.add(builder.equal(root.get(attributeIdentityProperty.getName()),
                        instance));
                criteria.where(predicates.toArray(new Predicate[predicates.size()]));

                List<?> results = em.createQuery(criteria).getResultList();
                for (Object result : results) {
                    em.remove(result);
                }
            }
            
            em.remove(instance);
        } catch (NoResultException ex) {
            throw new IdentityException(String.format(
                    "Exception removing identity object - [%s] not found.",
                    identity), ex);
        }
    }

    public void removeRelationship(IdentityStoreInvocationContext ctx,
                                   IdentityObject fromIdentity, IdentityObject toIdentity,
                                   IdentityObjectRelationshipType relationshipType,
                                   String relationshipName) throws IdentityException {
        Property<?> fromProperty = modelProperties.get(PROPERTY_RELATIONSHIP_FROM);
        Property<?> toProperty = modelProperties.get(PROPERTY_RELATIONSHIP_TO);
        Property<?> relationshipTypeProp = modelProperties.get(PROPERTY_RELATIONSHIP_TYPE);

        EntityManager em = getEntityManager(ctx);

        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<?> criteria = builder.createQuery(relationshipClass);
        Root<?> root = criteria.from(relationshipClass);

        List<Predicate> predicates = new ArrayList<Predicate>();
        predicates.add(builder.equal(root.get(fromProperty.getName()),
                lookupIdentity(fromIdentity, em)));
        predicates.add(builder.equal(root.get(toProperty.getName()),
                lookupIdentity(toIdentity, em)));
        predicates.add(builder.equal(root.get(relationshipTypeProp.getName()),
                lookupRelationshipType(relationshipType, em)));

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        Object relationship = em.createQuery(criteria).getSingleResult();
        em.remove(relationship);
    }

    public String removeRelationshipName(IdentityStoreInvocationContext ctx,
                                         String name) throws IdentityException, OperationNotSupportedException {
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

    public void removeRelationships(
            IdentityStoreInvocationContext ctx,
            IdentityObject identity1, IdentityObject identity2, boolean named)
            throws IdentityException {
        EntityManager em = getEntityManager(ctx);
        
        Object loadedIdentity1 = null;
        if(identity1 != null) {
        	loadedIdentity1 = lookupIdentity(identity1, em);
        }
        Object loadedIdentity2 = null;
        if(identity2 != null) {
        	loadedIdentity2 = lookupIdentity(identity2, em);
        }
        
        CriteriaBuilder builder = em.getCriteriaBuilder();
        CriteriaQuery<?> criteria = builder.createQuery(relationshipClass);
        Root<?> root = criteria.from(relationshipClass);
        
        Property<?> relationshipFromProp = modelProperties.get(PROPERTY_RELATIONSHIP_FROM);
        Property<?> relationshipToProp = modelProperties.get(PROPERTY_RELATIONSHIP_TO);

        List<Predicate> predicates = new ArrayList<Predicate>();
        
        if (identity1 != null) {
            predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
            		loadedIdentity1));
        }

        if (identity2 != null) {
            predicates.add(builder.equal(root.get(relationshipToProp.getName()),
            		loadedIdentity2));
        }

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        List<?> results = em.createQuery(criteria).getResultList();
        for (Object result : results) {
            em.remove(result);
        }

        criteria = builder.createQuery(relationshipClass);
        criteria.from(relationshipClass);

        predicates = new ArrayList<Predicate>();

        if (identity2 != null) {
            predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
            		loadedIdentity2));
        }
        if (identity1 != null) {
            predicates.add(builder.equal(root.get(relationshipToProp.getName()),
            		loadedIdentity1));
        }

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        results = em.createQuery(criteria).getResultList();
        for (Object result : results) {
            em.remove(result);
        }
    }

    public Set<IdentityObjectRelationship> resolveRelationships(
            IdentityStoreInvocationContext ctx,
            IdentityObject fromIdentity, IdentityObject toIdentity,
            IdentityObjectRelationshipType relationshipType)
            throws IdentityException {
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

        if (fromIdentity != null) {
            predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
                    lookupIdentity(fromIdentity, em)));
        }

        if (toIdentity != null) {
            predicates.add(builder.equal(root.get(relationshipToProp.getName()),
                    lookupIdentity(toIdentity, em)));
        }

        if (relationshipType != null) {
            predicates.add(builder.equal(root.get(relationshipTypeProp.getName()),
                    lookupRelationshipType(relationshipType, em)));
        }

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        List<?> results = em.createQuery(criteria).getResultList();

        EntityToSpiConverter converter = new EntityToSpiConverter();

        for (Object result : results) {
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
            boolean named, String name) throws IdentityException {
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

        if (parent) {
            predicates.add(builder.equal(root.get(relationshipFromProp.getName()),
                    lookupIdentity(identity, em)));
        } else {
            predicates.add(builder.equal(root.get(relationshipToProp.getName()),
                    lookupIdentity(identity, em)));
        }

        if (relationshipType != null) {
            predicates.add(builder.equal(root.get(relationshipTypeProp.getName()),
                    lookupRelationshipType(relationshipType, em)));
        }

        if (named) {
            if (name != null) {
                predicates.add(builder.equal(root.get(relationshipNameProp.getName()),
                        name));
            } else {
                predicates.add(builder.isNotNull(root.get(relationshipNameProp.getName())));
            }
        }

        criteria.where(predicates.toArray(new Predicate[predicates.size()]));

        List<?> results = em.createQuery(criteria).getResultList();

        EntityToSpiConverter converter = new EntityToSpiConverter();

        for (Object result : results) {
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

    public void updateCredential(IdentityStoreInvocationContext ctx,
                                 IdentityObject identityObject, IdentityObjectCredential credential)
            throws IdentityException {
        EntityManager em = getEntityManager(ctx);

        Property<Object> credentialValue = modelProperties.get(PROPERTY_CREDENTIAL_VALUE);

        if (credentialClass != null) {
            Property<Object> credentialIdentity = modelProperties.get(PROPERTY_CREDENTIAL_IDENTITY);
            Property<Object> credentialType = modelProperties.get(PROPERTY_CREDENTIAL_TYPE);
            Object identity = lookupIdentity(identityObject, em);

            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(credentialClass);
            Root<?> root = criteria.from(credentialClass);

            List<Predicate> predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(credentialIdentity.getName()),
                    identity));

            if (credentialType != null) {
                if (String.class.equals(credentialType.getJavaClass())) {
                    predicates.add(builder.equal(root.get(credentialType.getName()),
                            credential.getType().getName()));
                } else {
                    predicates.add(builder.equal(root.get(credentialType.getName()),
                            lookupCredentialTypeEntity(credential.getType().getName(), em)));
                }
            }

            criteria.where(predicates.toArray(new Predicate[predicates.size()]));

            List<?> results = em.createQuery(criteria).getResultList();

            if (results.isEmpty()) {
                // The credential doesn't exist, let's create it
                try {
                    Object newCredential = credentialClass.newInstance();
                    credentialIdentity.setValue(newCredential, identity);
                    credentialValue.setValue(newCredential, credential.getValue());
                    credentialType.setValue(newCredential,
                            lookupCredentialTypeEntity(credential.getType().getName(), em));

                    em.persist(newCredential);
                } catch (IllegalAccessException ex) {
                    throw new IdentityException("Error updating credential - could " +
                            "not create credential instance", ex);
                } catch (InstantiationException ex) {
                    throw new IdentityException("Error updating credential - could " +
                            "not create credential instance", ex);
                }
            } else {
                // TODO there shouldn't be multiple credentials with the same type,
                // but if there are, we need to deal with it somehow.. for now just use the first one

                Object result = results.get(0);
                credentialValue.setValue(result, credential.getValue());

                em.merge(result);
            }
        } else {
            // The credential is stored in the identity class, update it there

            Property<Object> credentialProp = modelProperties.get(PROPERTY_CREDENTIAL_VALUE);
            Object identity = lookupIdentity(identityObject, em);

            credentialProp.setValue(identity, credential.getValue());

            em.merge(identity);
        }

    }

    public boolean validateCredential(IdentityStoreInvocationContext ctx,
                                      IdentityObject identityObject, IdentityObjectCredential credential)
            throws IdentityException {
        EntityManager em = getEntityManager(ctx);

        Property<?> credentialValue = modelProperties.get(PROPERTY_CREDENTIAL_VALUE);

        // Either credentials are stored in their own class...
        if (credentialClass != null) {
            Property<?> credentialIdentity = modelProperties.get(PROPERTY_CREDENTIAL_IDENTITY);
            Property<?> credentialType = modelProperties.get(PROPERTY_CREDENTIAL_TYPE);

            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(credentialClass);
            Root<?> root = criteria.from(credentialClass);

            List<Predicate> predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(credentialIdentity.getName()),
                    lookupIdentity(identityObject, em)));

            if (credentialType != null) {
                if (String.class.equals(credentialType.getJavaClass())) {
                    predicates.add(builder.equal(root.get(credentialType.getName()),
                            credential.getType().getName()));
                } else {
                    predicates.add(builder.equal(root.get(credentialType.getName()),
                            lookupCredentialTypeEntity(credential.getType().getName(), em)));
                }
            }

            criteria.where(predicates.toArray(new Predicate[0]));

            List<?> results = em.createQuery(criteria).getResultList();

            if (results.isEmpty()) return false;

            // TODO this only supports plain text passwords

            for (Object result : results) {
                Object val = credentialValue.getValue(result);
                if (val.equals(credential.getValue())) return true;
            }
        }
        // or they're stored in the identity class
        else {
            Property<?> identityNameProp = modelProperties.get(PROPERTY_IDENTITY_NAME);

            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(credentialValue.getDeclaringClass());

            Root<?> root = criteria.from(credentialValue.getDeclaringClass());

            List<Predicate> predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(identityNameProp.getName()),
                    identityObject.getName()));

            criteria.where(predicates.toArray(new Predicate[predicates.size()]));

            Object result = em.createQuery(criteria).getSingleResult();

            Object val = credentialValue.getValue(result);
            if (val.equals(credential.getValue())) return true;
        }

        return false;
    }

    public void addAttributes(IdentityStoreInvocationContext ctx,
                              IdentityObject identityObject, IdentityObjectAttribute[] attributes)
            throws IdentityException {
        try {
            EntityManager em = getEntityManager(ctx);

            Object identity = lookupIdentity(identityObject, em);

            Set<IdentityObjectAttribute> filteredAttribs = new HashSet<IdentityObjectAttribute>();

            // Filter out the mapped attributes, and update their values
            for (IdentityObjectAttribute attrib : attributes) {
                if (attributeProperties.containsKey(attrib.getName())) {
                    MappedAttribute mappedAttribute = attributeProperties.get(attrib.getName());
                    if (mappedAttribute.getIdentityProperty() == null) {
                        mappedAttribute.getAttributeProperty().setValue(identity, attrib.getValue());
                    } else {
                        mappedAttribute.getAttributeProperty().setValue(mappedAttribute.getIdentityProperty().getValue(identity),
                                attrib.getValue());
                    }

                } else {
                    filteredAttribs.add(attrib);
                }
            }

            if (!filteredAttribs.isEmpty() && attributeClass != null) {
                Property<Object> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
                Property<Object> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
                Property<Object> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);

                for (IdentityObjectAttribute attrib : filteredAttribs) {
                    if (attrib.getSize() == 1) {
                        Object attribute = attributeClass.newInstance();
                        attributeIdentityProp.setValue(attribute, identity);
                        attributeNameProp.setValue(attribute, attrib.getName());
                        attributeValueProp.setValue(attribute, attrib.getValue());
                        em.persist(attribute);
                    } else {
                        for (Object value : attrib.getValues()) {
                            Object attribute = attributeClass.newInstance();
                            attributeIdentityProp.setValue(attribute, identity);
                            attributeNameProp.setValue(attribute, attrib.getName());
                            attributeValueProp.setValue(attribute, value);
                            em.persist(attribute);
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new IdentityException("Error while adding attributes.", e);
        }
    }

    public IdentityObjectAttribute getAttribute(IdentityStoreInvocationContext ctx,
                                                IdentityObject identity, String name) throws IdentityException {
        EntityManager em = getEntityManager(ctx);

        if (attributeProperties.containsKey(name)) {
            return getMappedAttribute(ctx, identity, name);
        } else {
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

            criteria.where(predicates.toArray(new Predicate[predicates.size()]));

            List<?> results = em.createQuery(criteria).getResultList();

            if (results.size() == 0) {
                // No results found, return an empty attribute value
                return new SimpleAttribute(name);
            } else if (results.size() == 1) {
                return new SimpleAttribute(name, attributeValueProp.getValue(results.get(0)));
            } else {
                Collection<Object> values = new ArrayList<Object>();
                for (Object result : results) {
                    values.add(attributeValueProp.getValue(result));
                }

                return new SimpleAttribute(name, values.toArray());
            }
        }
    }

    /**
     * Returns an attribute value stored elsewhere than the IDENTITY_ATTRIBUTES table
     *
     * @param ctx
     * @param identity
     * @param name
     * @return
     * @throws IdentityException
     */
    private IdentityObjectAttribute getMappedAttribute(IdentityStoreInvocationContext ctx,
            IdentityObject identity, String name) throws IdentityException {
        MappedAttribute mappedAttribute = attributeProperties.get(name);

        EntityManager em = getEntityManager(ctx);

        if (mappedAttribute.getIdentityProperty() == null) {
            // The attribute value is stored in the identity object itself
            return new SimpleAttribute(name, mappedAttribute.getAttributeProperty().getValue(lookupIdentity(identity, em)));
        } else {
            // The attribute value is stored in an object referenced by the identity object
            return new SimpleAttribute(name, mappedAttribute.getAttributeProperty().getValue(
                    mappedAttribute.getIdentityProperty().getValue(lookupIdentity(identity, em))));
        }
    }

    public Map<String, IdentityObjectAttribute> getAttributes(
            IdentityStoreInvocationContext ctx,
            IdentityObject identityObject) throws IdentityException {

        Map<String, IdentityObjectAttribute> attributes = new HashMap<String, IdentityObjectAttribute>();

        EntityManager em = getEntityManager(ctx);

        Object identity = lookupIdentity(identityObject, em);

        for (String name : attributeProperties.keySet()) {
            attributes.put(name, getMappedAttribute(ctx, identityObject, name));
        }

        if (attributeClass != null) {
            Property<?> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
            Property<?> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
            Property<?> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);

            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
            Root<?> root = criteria.from(attributeClass);

            List<Predicate> predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(attributeIdentityProp.getName()),
                    identity));

            criteria.where(predicates.toArray(new Predicate[predicates.size()]));

            List<?> results = em.createQuery(criteria).getResultList();

            for (Object result : results) {
                String name = attributeNameProp.getValue(result).toString();
                Object value = attributeValueProp.getValue(result);

                if (attributes.containsKey(name)) {
                    IdentityObjectAttribute attr = attributes.get(name);
                    attr.addValue(value);
                } else {
                    attributes.put(name, new SimpleAttribute(name, value));
                }
            }
        }

        return attributes;
    }

    /**
     * Removes the attributes specified by the attributeNames property.  Mapped attributes cannot be
     * removed via this method, instead their values must be overwritten using updateAttributes()
     */
    public void removeAttributes(IdentityStoreInvocationContext ctx,
                                 IdentityObject identityObject, String[] attributeNames)
            throws IdentityException {
        EntityManager em = getEntityManager(ctx);

        Object identity = lookupIdentity(identityObject, em);

        if (attributeClass != null) {
            Property<?> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
            Property<?> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);

            CriteriaBuilder builder = em.getCriteriaBuilder();
            CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
            Root<?> root = criteria.from(attributeClass);

            List<Predicate> predicates = new ArrayList<Predicate>();
            predicates.add(builder.equal(root.get(attributeIdentityProp.getName()),
                    identity));

            criteria.where(predicates.toArray(new Predicate[predicates.size()]));

            List<?> results = em.createQuery(criteria).getResultList();

            for (Object result : results) {
                String name = attributeNameProp.getValue(result).toString();
                for (String n : attributeNames) {
                    if (name != null && name.equals(n)) {
                        em.remove(result);
                        break;
                    }
                }
            }
        }
    }

    public void updateAttributes(IdentityStoreInvocationContext ctx,
                                 IdentityObject identityObject, IdentityObjectAttribute[] attributes)
            throws IdentityException {
        try {
            EntityManager em = getEntityManager(ctx);

            Object identity = lookupIdentity(identityObject, em);

            Set<IdentityObjectAttribute> filteredAttribs = new HashSet<IdentityObjectAttribute>();

            // First we need to filter out the mapped attributes, and while we're at it we'll update their values
            for (IdentityObjectAttribute attrib : attributes) {
                if (attributeProperties.containsKey(attrib.getName())) {
                    MappedAttribute mappedAttribute = attributeProperties.get(attrib.getName());
                    if (mappedAttribute.getIdentityProperty() == null) {
                        mappedAttribute.getAttributeProperty().setValue(identity, attrib.getValue());
                    } else {
                        mappedAttribute.getAttributeProperty().setValue(mappedAttribute.getIdentityProperty().getValue(identity),
                                attrib.getValue());
                    }

                } else {
                    filteredAttribs.add(attrib);
                }
            }

            // Now we'll update the remaining, non-mapped attribute values
            if (attributeClass != null) {
                Property<Object> attributeIdentityProp = modelProperties.get(PROPERTY_ATTRIBUTE_IDENTITY);
                Property<Object> attributeNameProp = modelProperties.get(PROPERTY_ATTRIBUTE_NAME);
                Property<Object> attributeValueProp = modelProperties.get(PROPERTY_ATTRIBUTE_VALUE);
                Property<Object> attributeTypeProp = modelProperties.get(PROPERTY_ATTRIBUTE_TYPE);

                for (IdentityObjectAttribute attrib : filteredAttribs) {
                    CriteriaBuilder builder = em.getCriteriaBuilder();
                    CriteriaQuery<?> criteria = builder.createQuery(attributeClass);
                    Root<?> root = criteria.from(attributeClass);

                    List<Predicate> predicates = new ArrayList<Predicate>();
                    predicates.add(builder.equal(root.get(attributeIdentityProp.getName()),
                            identity));
                    predicates.add(builder.equal(root.get(attributeNameProp.getName()),
                            attrib.getName()));

                    criteria.where(predicates.toArray(new Predicate[predicates.size()]));

                    List<?> results = em.createQuery(criteria).getResultList();

                    // All existing attribute values should be overwritten, so we
                    // will first remove them, then add the new values

                    if (!results.isEmpty()) {
                        for (Object result : results) {
                            em.remove(result);
                        }
                    }

                    for (Object value : attrib.getValues()) {
                        Object attribute = attributeClass.newInstance();
                        attributeIdentityProp.setValue(attribute, identity);
                        attributeNameProp.setValue(attribute, attrib.getName());

                        // If there is an attribute type property, then determine the value type
                        // TODO this is messy, refactor it by abstracting into a utility class
                        if (attributeTypeProp != null) {
                            if (String.class.equals(value.getClass())) {
                                attributeValueProp.setValue(attribute, value.toString());
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_TEXT);
                            } else if (Boolean.class.equals(value.getClass()) || Boolean.TYPE.equals(value.getClass())) {
                                attributeValueProp.setValue(attribute, Boolean.toString((Boolean) value));
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_BOOLEAN);
                            } else if (Date.class.isAssignableFrom(value.getClass())) {
                                attributeValueProp.setValue(attribute, "" + ((Date) value).getTime());
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_DATE);
                            } else if (Integer.class.equals(value.getClass()) || Integer.TYPE.equals(value.getClass())) {
                                attributeValueProp.setValue(attribute, ((Integer) value).toString());
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_INT);
                            } else if (Long.class.equals(value.getClass()) || Long.TYPE.equals(value.getClass())) {
                                attributeValueProp.setValue(attribute, ((Long) value).toString());
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_LONG);
                            } else if (Float.class.equals(value.getClass()) || Float.TYPE.equals(value.getClass())) {
                                attributeValueProp.setValue(attribute, ((Float) value).toString());
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_FLOAT);
                            } else if (Double.class.equals(value.getClass()) || Double.TYPE.equals(value.getClass())) {
                                attributeValueProp.setValue(attribute, ((Double) value).toString());
                                attributeTypeProp.setValue(attribute, ATTRIBUTE_TYPE_DOUBLE);
                            } else {
                                throw new IdentityException("Could not persist attribute value - unsupported attribute value type " +
                                        value.getClass());
                            }
                        } else {
                            attributeValueProp.setValue(attribute, value.toString());
                        }

                        em.persist(attribute);
                    }
                }
            }
        } catch (Exception e) {
            throw new IdentityException("Error while updating attributes.", e);
        }
    }

    public IdentityStoreSession createIdentityStoreSession()
            throws IdentityException {
        return createIdentityStoreSession(null);
    }

    public Collection<IdentityObject> findIdentityObject(IdentityStoreInvocationContext invocationCxt, IdentityObject identity,
            IdentityObjectRelationshipType relationshipType, boolean parent, IdentityObjectSearchCriteria criteria)
            throws IdentityException {
        List<IdentityObject> objs = new ArrayList<IdentityObject>();

        EntityManager em = getEntityManager(invocationCxt);
        javax.persistence.Query q = null;

        boolean orderByName = false;
        boolean ascending = true;

        if (criteria != null && criteria.isSorted()) {
            orderByName = true;
            ascending = criteria.isAscending();
        }

        StringBuilder queryString = new StringBuilder();

        IdentityObjectType identityType = identity.getIdentityType();

        Object identType = modelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME) ? lookupIdentityType(
                identityType.getName(), getEntityManager(invocationCxt)) : identityType.getName();

        final String identEntityAnnotationValue = identityClass.getAnnotation(Entity.class).name();
        final String identEntityName = ("".equals(identEntityAnnotationValue) ? identityClass.getSimpleName() : identEntityAnnotationValue);

        Object ident = getEntityManager(invocationCxt).createQuery(
                        "select i from " + identEntityName + " i where i."
                                + modelProperties.get(PROPERTY_IDENTITY_NAME).getName() + " = :name and i."
                                + modelProperties.get(PROPERTY_IDENTITY_TYPE).getName() + " = :type")
                .setParameter("name", identity.getName()).setParameter("type", identType).getSingleResult();

        String relEntityName = "";
        if (modelProperties.get(PROPERTY_RELATIONSHIP_NAME) != null) {
            final Class<?> relationshipClass = modelProperties.get(PROPERTY_RELATIONSHIP_NAME).getDeclaringClass();
            final String relEntityAnnotationValue = relationshipClass.getAnnotation(Entity.class).name();
            relEntityName = ("".equals(identEntityAnnotationValue) ? relationshipClass.getSimpleName() : relEntityAnnotationValue);
        }

        if (parent) {
            if (relationshipType != null) {
                queryString.append("select distinct ior." + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + " from "
                        + relEntityName + " ior where ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + "."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_NAME).getName() + " like :nameFilter and ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getName() + "."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME).getName() + " = :relType and ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_FROM).getName() + " = :identity");
            } else {
                queryString.append("select distinct ior. " + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + "from "
                        + relEntityName + " ior where ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + "."
                        + modelProperties.get(PROPERTY_IDENTITY_NAME).getName() + " like :nameFilter and ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_FROM).getName() + " = :identity");
            }
            if (orderByName) {
                queryString.append(" order by ior." + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + "."
                        + modelProperties.get(PROPERTY_IDENTITY_NAME).getName() + (ascending ? " asc" : ""));
            }
        } else {
            if (relationshipType != null) {
                queryString.append("select distinct ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_FROM).getName() + " from "
                        + relEntityName + " ior where ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_FROM).getName() + "."
                        + modelProperties.get(PROPERTY_IDENTITY_NAME).getName() + " like :nameFilter and ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getName() + "."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME).getName() + " = :relType and ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + " = :identity");
            } else {
                queryString.append("select distinct ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_FROM).getName() + " from "
                        + relEntityName + " ior where ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_FROM).getName() + "."
                        + modelProperties.get(PROPERTY_IDENTITY_NAME).getName() + " like :nameFilter and ior."
                        + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + " = :identity");
            }

            if (orderByName) {
                queryString.append(" order by ior." + modelProperties.get(PROPERTY_RELATIONSHIP_TO).getName() + "."
                        + modelProperties.get(PROPERTY_IDENTITY_NAME).getName() + (ascending ? " asc" : ""));
            }

        }

        q = em.createQuery(queryString.toString()).setParameter("identity", ident);

        if (relationshipType != null) {
            q.setParameter("relType", relationshipType.getName());
        }

        if (criteria != null && criteria.getFilter() != null) {
            q.setParameter("nameFilter", criteria.getFilter().replaceAll("\\*", "%"));
        } else {
            q.setParameter("nameFilter", "%");
        }

        if (criteria != null && criteria.isPaged() && !criteria.isFiltered()) {
            q.setFirstResult(criteria.getFirstResult());
            if (criteria.getMaxResults() > 0) {
                q.setMaxResults(criteria.getMaxResults());
            }
        }

        List<?> results = q.getResultList();

        EntityToSpiConverter converter = new EntityToSpiConverter();

        for (Object result : results) {
            objs.add(converter.convertToIdentityObject(result));
        }

        return objs;
    }

    public IdentityObject findIdentityObjectByUniqueAttribute(
            IdentityStoreInvocationContext invocationCtx,
            IdentityObjectType identityObjectType,
            IdentityObjectAttribute attribute) throws IdentityException {
        // TODO Auto-generated method stub
        return null;
    }

    public Map<String, IdentityObjectAttributeMetaData> getAttributesMetaData(
            IdentityStoreInvocationContext invocationContext,
            IdentityObjectType identityType) {
        // TODO Auto-generated method stub
        return null;
    }

    public Set<String> getSupportedAttributeNames(
            IdentityStoreInvocationContext invocationContext,
            IdentityObjectType identityType) throws IdentityException {
        // TODO Auto-generated method stub
        return null;
    }

    public int getIdentityObjectsCount(
            IdentityStoreInvocationContext invocationCtx,
            IdentityObjectType identityType) throws IdentityException {
        System.out.println("*** Invoked unimplemented method getIdentityObjectsCount()");
        // TODO Auto-generated method stub
        return 0;
    }

    public Map<String, String> getRelationshipNameProperties(
            IdentityStoreInvocationContext ctx, String name)
            throws IdentityException, OperationNotSupportedException {
        throw new OperationNotSupportedException("getRelationshipNameProperties() not supported");
    }

    public void setRelationshipNameProperties(
            IdentityStoreInvocationContext ctx, String name,
            Map<String, String> properties) throws IdentityException,
            OperationNotSupportedException {
        throw new OperationNotSupportedException("setRelationshipNameProperties() not supported");
    }

    public void setRelationshipProperties(IdentityStoreInvocationContext ctx,
                                          IdentityObjectRelationship relationship, Map<String, String> properties)
            throws IdentityException, OperationNotSupportedException {
        throw new OperationNotSupportedException("setRelationshipProperties() not supported");
    }

    public void removeRelationshipNameProperties(
            IdentityStoreInvocationContext ctx, String name, Set<String> properties)
            throws IdentityException, OperationNotSupportedException {
        throw new OperationNotSupportedException("removeRelationshipNameProperties() not supported");
    }

    public void removeRelationshipProperties(IdentityStoreInvocationContext ctx,
                                             IdentityObjectRelationship relationship, Set<String> properties)
            throws IdentityException, OperationNotSupportedException {
        throw new OperationNotSupportedException("removeRelationshipProperties() not supported");
    }
}
