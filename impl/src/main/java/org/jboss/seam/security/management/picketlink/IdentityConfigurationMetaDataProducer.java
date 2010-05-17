package org.jboss.seam.security.management.picketlink;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

import org.picketlink.idm.impl.configuration.metadata.IdentityConfigurationMetaDataImpl;
import org.picketlink.idm.spi.configuration.metadata.IdentityConfigurationMetaData;

/**
 * Produces the configuration metadata for PicketLink IDM
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class IdentityConfigurationMetaDataProducer
{
   @Produces @ApplicationScoped IdentityConfigurationMetaData createConfig()
   {
      // TODO needs actual configuration, realms, identity stores, etc
      return new IdentityConfigurationMetaDataImpl();
   }
}
