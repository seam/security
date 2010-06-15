package org.jboss.seam.security.management.picketlink;

import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.IdentitySessionFactory;
import org.picketlink.idm.common.exception.IdentityConfigurationException;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.configuration.IdentityConfigurationImpl;
import org.picketlink.idm.impl.configuration.metadata.IdentityConfigurationMetaDataImpl;
import org.picketlink.idm.impl.configuration.metadata.IdentityStoreConfigurationMetaDataImpl;
import org.picketlink.idm.impl.configuration.metadata.RealmConfigurationMetaDataImpl;
import org.picketlink.idm.spi.configuration.metadata.IdentityConfigurationMetaData;
import org.picketlink.idm.spi.configuration.metadata.IdentityStoreConfigurationMetaData;
import org.picketlink.idm.spi.configuration.metadata.RealmConfigurationMetaData;

/**
 * Produces IdentitySession instances for identity management-related operations
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class IdentitySessionProducer
{
   private IdentitySessionFactory factory;
   
   private String defaultRealm = "default";
   
   @Inject IdentityConfigurationMetaData config;
   
   @Inject
   public void init() throws IdentityConfigurationException
   {
      IdentityConfigurationMetaDataImpl metadata = new IdentityConfigurationMetaDataImpl();

      // Create the identity store configuration
      List<IdentityStoreConfigurationMetaData> stores = new ArrayList<IdentityStoreConfigurationMetaData>();      
      IdentityStoreConfigurationMetaDataImpl store = new IdentityStoreConfigurationMetaDataImpl();
      store.setId("jpa");
      store.setClassName("org.jboss.seam.security.management.JpaIdentityStore");
      stores.add(store);            
      metadata.setIdentityStores(stores);
      
      // Create the default realm
      RealmConfigurationMetaDataImpl realm = new RealmConfigurationMetaDataImpl();
      realm.setIdentityRepositoryIdRef("jpa");
      realm.setId("default");      
      List<RealmConfigurationMetaData> realms = new ArrayList<RealmConfigurationMetaData>();      
      realms.add(realm);
      metadata.setRealms(realms);
            
      IdentityConfigurationImpl config = new IdentityConfigurationImpl();
      config.configure(metadata);
      
      factory = config.buildIdentitySessionFactory();      
   }
   
   @Produces @RequestScoped IdentitySession createIdentitySession()
      throws IdentityException
   {
      return factory.createIdentitySession(getDefaultRealm());
   }
   
   public String getDefaultRealm()
   {
      return defaultRealm;
   }
   
   public void setDefaultRealm(String defaultRealm)
   {
      this.defaultRealm = defaultRealm;
   }
}
