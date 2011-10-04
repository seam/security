package org.jboss.seam.security.management.picketlink;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.persistence.Entity;

import org.jboss.seam.security.annotations.management.IdentityEntity;
import org.picketlink.idm.impl.configuration.metadata.IdentityStoreConfigurationMetaDataImpl;

/**
 * A convenience class for setting JpaIdentityStore configuration options.
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class JpaIdentityStoreConfiguration extends IdentityStoreConfiguration implements Extension {

    private Class<?> identityClass;
    private Class<?> credentialClass;
    private Class<?> relationshipClass;
    private Class<?> roleTypeClass;
    private Class<?> attributeClass;

    public <X> void processAnnotatedType(@Observes ProcessAnnotatedType<X> event,
            final BeanManager beanManager) {
        
        if (event.getAnnotatedType().isAnnotationPresent(Entity.class)) {
            AnnotatedType<X> type = event.getAnnotatedType();
            
            if (type.isAnnotationPresent(IdentityEntity.class)) {
                IdentityEntity a = type.getAnnotation(IdentityEntity.class);
                
                switch(a.value()) { 
                    case IDENTITY_OBJECT: 
                        identityClass = type.getJavaClass();
                        break;
                    case IDENTITY_CREDENTIAL:
                        credentialClass = type.getJavaClass();
                        break;
                    case IDENTITY_RELATIONSHIP: 
                        relationshipClass = type.getJavaClass();
                        break;
                    case IDENTITY_ATTRIBUTE:
                        attributeClass = type.getJavaClass();
                        break;
                    case IDENTITY_ROLE_NAME:
                        roleTypeClass = type.getJavaClass();
                        break;   
                }
            }
        }        
    }
    
    
    @Override
    public String getId() {
        return (super.getId() == null) ? "jpa" : super.getId();
    }

    /**
     * If the identityStoreClass hasn't been set, then return JpaIdentityStore by default.
     */
    @Override
    public Class<?> getIdentityStoreClass() {
        return (super.getIdentityStoreClass() == null) ? JpaIdentityStore.class : super.getIdentityStoreClass();
    }

    public Class<?> getIdentityClass() {
        return identityClass;
    }

    public void setIdentityClass(Class<?> identityClass) {
        this.identityClass = identityClass;
    }

    public Class<?> getCredentialClass() {
        return credentialClass;
    }

    public void setCredentialClass(Class<?> credentialClass) {
        this.credentialClass = credentialClass;
    }

    public Class<?> getRelationshipClass() {
        return relationshipClass;
    }

    public void setRelationshipClass(Class<?> relationshipClass) {
        this.relationshipClass = relationshipClass;
    }

    public Class<?> getRoleTypeClass() {
        return roleTypeClass;
    }

    public void setRoleTypeClass(Class<?> roleTypeClass) {
        this.roleTypeClass = roleTypeClass;
    }

    public Class<?> getAttributeClass() {
        return attributeClass;
    }

    public void setAttributeClass(Class<?> attributeClass) {
        this.attributeClass = attributeClass;
    }

    public void doConfigure(IdentityStoreConfigurationMetaDataImpl store) {
        Map<String, List<String>> options = new HashMap<String, List<String>>();

        if (identityClass != null) {
            options.put(JpaIdentityStore.OPTION_IDENTITY_CLASS_NAME, createOptionList(identityClass.getName()));
        }

        if (credentialClass != null) {
            options.put(JpaIdentityStore.OPTION_CREDENTIAL_CLASS_NAME, createOptionList(credentialClass.getName()));
        }

        if (relationshipClass != null) {
            options.put(JpaIdentityStore.OPTION_RELATIONSHIP_CLASS_NAME, createOptionList(relationshipClass.getName()));
        }

        if (roleTypeClass != null) {
            options.put(JpaIdentityStore.OPTION_ROLE_TYPE_CLASS_NAME, createOptionList(roleTypeClass.getName()));
        }

        if (attributeClass != null) {
            options.put(JpaIdentityStore.OPTION_ATTRIBUTE_CLASS_NAME, createOptionList(attributeClass.getName()));
        }

        store.setOptions(options);
    }

    public boolean isConfigured() {
        return identityClass != null;
    }

    private List<String> createOptionList(String... values) {
        List<String> vals = new ArrayList<String>();
        for (String v : values)
            vals.add(v);
        return vals;
    }
}
