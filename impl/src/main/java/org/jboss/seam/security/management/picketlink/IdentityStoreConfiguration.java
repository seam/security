package org.jboss.seam.security.management.picketlink;

import org.picketlink.idm.impl.configuration.metadata.IdentityStoreConfigurationMetaDataImpl;

/**
 * Abstract bean for configuring identity stores
 *
 * @author Shane Bryzak
 */
public abstract class IdentityStoreConfiguration {
    private String id;
    private Class<?> identityStoreClass;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Class<?> getIdentityStoreClass() {
        return identityStoreClass;
    }

    public void setIdentityStoreClass(Class<?> identityStoreClass) {
        this.identityStoreClass = identityStoreClass;
    }

    public void configure(IdentityStoreConfigurationMetaDataImpl store) {
        store.setId(getId());

        if (getIdentityStoreClass() != null) {
            store.setClassName(getIdentityStoreClass().getName());
        }

        doConfigure(store);
    }

    public abstract void doConfigure(IdentityStoreConfigurationMetaDataImpl store);

    public abstract boolean isConfigured();
}
