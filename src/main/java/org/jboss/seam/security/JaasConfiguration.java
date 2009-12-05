package org.jboss.seam.security;

import java.util.HashMap;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.jboss.seam.security.jaas.SeamLoginModule;

/**
 * Producer for the JAAS Configuration used by Seam Security.
 * 
 * @author Shane Bryzak
 *
 */
public class JaasConfiguration
{
   static final String DEFAULT_JAAS_CONFIG_NAME = "default";

   protected Configuration createConfiguration()
   {
      return new Configuration()
      {
         private AppConfigurationEntry[] aces = { createAppConfigurationEntry() };
         
         @Override
         public AppConfigurationEntry[] getAppConfigurationEntry(String name)
         {
            return DEFAULT_JAAS_CONFIG_NAME.equals(name) ? aces : null;
         }
         
         @Override
         public void refresh() {}
      };
   }

   protected AppConfigurationEntry createAppConfigurationEntry()
   {
      return new AppConfigurationEntry(
            SeamLoginModule.class.getName(),
            LoginModuleControlFlag.REQUIRED,
            new HashMap<String,String>()
         );
   }
   
   @Produces @ApplicationScoped Configuration getConfiguration()
   {
      return createConfiguration();
   }
}
