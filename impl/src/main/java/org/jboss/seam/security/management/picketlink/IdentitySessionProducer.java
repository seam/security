package org.jboss.seam.security.management.picketlink;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.event.Event;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.persistence.EntityManager;

import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.IdentitySessionFactory;
import org.picketlink.idm.api.cfg.IdentityConfiguration;
import org.picketlink.idm.api.event.EventListener;
import org.picketlink.idm.common.exception.IdentityConfigurationException;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.configuration.IdentityConfigurationImpl;
import org.picketlink.idm.impl.configuration.metadata.IdentityConfigurationMetaDataImpl;
import org.picketlink.idm.impl.configuration.metadata.IdentityRepositoryConfigurationMetaDataImpl;
import org.picketlink.idm.impl.configuration.metadata.IdentityStoreConfigurationMetaDataImpl;
import org.picketlink.idm.impl.configuration.metadata.IdentityStoreMappingMetaDataImpl;
import org.picketlink.idm.impl.configuration.metadata.RealmConfigurationMetaDataImpl;
import org.picketlink.idm.impl.repository.WrapperIdentityStoreRepository;
import org.picketlink.idm.spi.configuration.metadata.IdentityConfigurationMetaData;
import org.picketlink.idm.spi.configuration.metadata.IdentityRepositoryConfigurationMetaData;
import org.picketlink.idm.spi.configuration.metadata.IdentityStoreConfigurationMetaData;
import org.picketlink.idm.spi.configuration.metadata.IdentityStoreMappingMetaData;
import org.picketlink.idm.spi.configuration.metadata.RealmConfigurationMetaData;

/**
 * Produces IdentitySession instances for identity management-related operations
 *
 * @author Shane Bryzak
 */
@ApplicationScoped
public class IdentitySessionProducer implements EventListener {
   
    public static final String SESSION_OPTION_ENTITY_MANAGER = "ENTITY_MANAGER";
    public static final String SESSION_OPTION_IDENTITY_OBJECT_CREATED_EVENT = "IDENTITY_OBJECT_CREATED_EVENT";

    private String defaultRealm = "default";
    private String defaultAttributeStoreId;
    private String defaultIdentityStoreId;
    
    IdentityConfigurationMetaData metadata; 
    
    // Flag that indicates whether any identity stores have been configured.
    private boolean configured;

    @Inject
    BeanManager manager;

    @Inject
    public void init() throws IdentityConfigurationException, IdentityException {
        metadata = new IdentityConfigurationMetaDataImpl();

        // Create the identity store configuration
        List<IdentityStoreConfigurationMetaData> stores = new ArrayList<IdentityStoreConfigurationMetaData>();

        String defaultStoreId = null;

        Set<Bean<?>> storeBeans = manager.getBeans(IdentityStoreConfiguration.class);
        for (Bean<?> storeBean : storeBeans) {
            IdentityStoreConfiguration config = (IdentityStoreConfiguration) manager
                    .getReference(storeBean, IdentityStoreConfiguration.class,
                            manager.createCreationalContext(storeBean));

            if (config.isConfigured()) {
                IdentityStoreConfigurationMetaDataImpl storeConfig = new IdentityStoreConfigurationMetaDataImpl();
                config.configure(storeConfig);
                stores.add(storeConfig);

                if (defaultStoreId == null && storeConfig.getId() != null) {
                    defaultStoreId = storeConfig.getId();
                }
            }
        }

        ((IdentityConfigurationMetaDataImpl) metadata).setIdentityStores(stores);

        // Create the default realm
        RealmConfigurationMetaDataImpl realm = new RealmConfigurationMetaDataImpl();
        realm.setId(getDefaultRealm());
        realm.setIdentityMapping("USER");
        //realm.setGroupTypeMappings(groupTypeMappings)
        realm.setOptions(new HashMap<String, List<String>>());
        List<RealmConfigurationMetaData> realms = new ArrayList<RealmConfigurationMetaData>();
        realms.add(realm);
        ((IdentityConfigurationMetaDataImpl) metadata).setRealms(realms);

        if (stores.size() > 0) {
            List<IdentityRepositoryConfigurationMetaData> repositories = new ArrayList<IdentityRepositoryConfigurationMetaData>();

            IdentityRepositoryConfigurationMetaDataImpl repository = new IdentityRepositoryConfigurationMetaDataImpl();
            repository.setClassName(WrapperIdentityStoreRepository.class.getName());
            repository.setDefaultAttributeStoreId(defaultAttributeStoreId != null ? defaultAttributeStoreId : defaultStoreId);
            repository.setDefaultIdentityStoreId(defaultIdentityStoreId != null ? defaultIdentityStoreId : defaultStoreId);

            List<IdentityStoreMappingMetaData> mappings = new ArrayList<IdentityStoreMappingMetaData>();

            IdentityStoreMappingMetaDataImpl mapping = new IdentityStoreMappingMetaDataImpl();
            List<String> identityObjectTypes = new ArrayList<String>();
            identityObjectTypes.add("USER");
            identityObjectTypes.add("GROUP");
            mapping.setIdentityObjectTypeMappings(identityObjectTypes);
            mapping.setIdentityStoreId(defaultIdentityStoreId != null ? defaultIdentityStoreId : defaultStoreId);
            mappings.add(mapping);

            repository.setIdentityStoreToIdentityObjectTypeMappings(mappings);

            repositories.add(repository);
            ((IdentityConfigurationMetaDataImpl) metadata).setRepositories(repositories);
            
            configured = true;
        }
        
    }
    
    /**
     * This method can be used to determine whether identity management has been configured for the application.
     * 
     * @return
     */
    public boolean isConfigured() {
        return configured;
    }

    @Inject
    Instance<EntityManager> entityManagerInstance;
    
    @Inject
    Event<IdentityObjectCreatedEvent> identityObjectCreatedEvent;
    
    @Produces 
    public IdentitySessionFactory produceFactory() throws IdentityConfigurationException {
        IdentityConfigurationImpl config = new IdentityConfigurationImpl();
        config.configure(metadata);
        return config.buildIdentitySessionFactory();
    }

    @Produces
    @RequestScoped
    IdentitySession createIdentitySession(IdentitySessionFactory factory)
            throws IdentityException {
        
        if (metadata.getRepositories() == null || metadata.getRepositories().size() == 0) {
            throw new IdentityException("Error creating IdentitySession - no PicketLink IdentityStore repositories have been configured.");
        }
        
        Map<String, Object> sessionOptions = new HashMap<String, Object>();

        if (!entityManagerInstance.isUnsatisfied() && !entityManagerInstance.isAmbiguous()) {
            sessionOptions.put(SESSION_OPTION_ENTITY_MANAGER, entityManagerInstance.get());
            sessionOptions.put(SESSION_OPTION_IDENTITY_OBJECT_CREATED_EVENT, identityObjectCreatedEvent);
        }
            
        IdentitySession session = factory.createIdentitySession(getDefaultRealm(), sessionOptions);
        session.registerListener(this);
        return session;
    }

    public String getDefaultRealm() {
        return defaultRealm;
    }

    public void setDefaultRealm(String defaultRealm) {
        this.defaultRealm = defaultRealm;
    }

    public String getDefaultAttributeStoreId() {
        return defaultAttributeStoreId;
    }

    public void setDefaultAttributeStoreId(String defaultAttributeStoreId) {
        this.defaultAttributeStoreId = defaultAttributeStoreId;
    }

    public String getDefaultIdentityStoreId() {
        return defaultIdentityStoreId;
    }

    public void setDefaultIdentityStoreId(String defaultIdentityStoreId) {
        this.defaultIdentityStoreId = defaultIdentityStoreId;
    }
}
