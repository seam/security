package org.jboss.seam.security.management.picketlink;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.IdentitySessionFactory;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.api.IdentitySessionFactoryImpl;
import org.picketlink.idm.spi.configuration.metadata.IdentityConfigurationMetaData;

/**
 * Produces IdentitySession instances for identity management-related operations
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class IdentitySessionProducer
{
   private IdentitySessionFactory factory;
   
   private String defaultRealm;
   
   @Inject IdentityConfigurationMetaData config;
   
   @Inject
   public void init()
   {
      factory = new IdentitySessionFactoryImpl(config, null);
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
