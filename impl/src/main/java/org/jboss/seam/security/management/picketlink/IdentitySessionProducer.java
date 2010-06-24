package org.jboss.seam.security.management.picketlink;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.persistence.EntityManager;

import org.jboss.seam.security.management.JpaIdentityStore;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.IdentitySessionFactory;
import org.picketlink.idm.api.event.EventListener;
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
public class IdentitySessionProducer implements EventListener
{
   private IdentitySessionFactory factory;
   
   private String defaultRealm = "default";
   
   @Inject IdentityConfigurationMetaData config;
   
   @Inject
   public void init() throws IdentityConfigurationException, IdentityException
   {
      IdentityConfigurationMetaDataImpl metadata = new IdentityConfigurationMetaDataImpl();

      // Create the identity store configuration
      List<IdentityStoreConfigurationMetaData> stores = new ArrayList<IdentityStoreConfigurationMetaData>();      
      IdentityStoreConfigurationMetaDataImpl store = new IdentityStoreConfigurationMetaDataImpl();
      store.setId("jpa");
      store.setClassName("org.jboss.seam.security.management.JpaIdentityStore");      
      
      // temporary hack
      Map<String,List<String>> options = new HashMap<String,List<String>>();
      options.put(JpaIdentityStore.OPTION_IDENTITY_CLASS_NAME, 
            createOptionList("org.jboss.seam.security.examples.idmconsole.model.IdentityObject"));
      
      
      store.setOptions(options);
      stores.add(store);            
      metadata.setIdentityStores(stores);
      
      // Create the default realm
      RealmConfigurationMetaDataImpl realm = new RealmConfigurationMetaDataImpl();
      realm.setId("default");      
      List<RealmConfigurationMetaData> realms = new ArrayList<RealmConfigurationMetaData>();      
      realms.add(realm);
      metadata.setRealms(realms);
            
      IdentityConfigurationImpl config = new IdentityConfigurationImpl();
      config.configure(metadata);
      config.register(this, "identitySessionProducer");
      
      factory = config.buildIdentitySessionFactory();      
   }
   
   private List<String> createOptionList(String... values)
   {
      List<String> vals = new ArrayList<String>();
      for (String v : values) vals.add(v);
      return vals;
   }
   
   @Inject Instance<EntityManager> entityManagerInstance;
      
   @Produces @RequestScoped IdentitySession createIdentitySession()
      throws IdentityException
   {
      Map<String,Object> sessionOptions = new HashMap<String,Object>();
      sessionOptions.put("ENTITY_MANAGER", entityManagerInstance.get());      
      IdentitySession session = factory.createIdentitySession(getDefaultRealm(), sessionOptions);
      session.registerListener(this);
      return session;
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
