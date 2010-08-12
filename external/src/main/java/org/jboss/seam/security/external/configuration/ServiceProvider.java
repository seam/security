/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.seam.security.external.configuration;

import java.net.MalformedURLException;
import java.net.URL;

import javax.el.MethodExpression;

import org.jboss.seam.security.external.ExternalAuthenticationService;
import org.jboss.seam.security.external.jaxb.config.ServiceProviderType;

public class ServiceProvider
{
   private Configuration configuration;

   private SamlConfiguration samlConfiguration;

   private OpenIdConfiguration openIdConfiguration;

   private String hostname;

   private String protocol;

   private int port;

   private String loggedOutUrl;

   private String unsolicitedAuthenticationUrl;

   private String failedAuthenticationUrl;

   private MethodExpression internalAuthenticationMethod;

   public ServiceProvider(Configuration configuration, ServiceProviderType serviceProvider)
   {
      this.configuration = configuration;

      hostname = serviceProvider.getHostname();
      protocol = serviceProvider.getProtocol().value();

      loggedOutUrl = serviceProvider.getLoggedOutUrl();
      unsolicitedAuthenticationUrl = serviceProvider.getUnsolicitedAuthenticationUrl();
      failedAuthenticationUrl = serviceProvider.getFailedAuthenticationUrl();

      internalAuthenticationMethod = null; // FIXME =
      // Expressions.instance().createMethodExpression(serviceProvider.getInternalAuthenticationMethod(),
      // Boolean.class, Principal.class,
      // List.class);

      if (serviceProvider.getPort() == null)
      {
         if (protocol.equals("http"))
         {
            port = 8080;
         }
         else
         {
            port = 8443;
         }
      }
      else
      {
         port = serviceProvider.getPort().intValue();
      }

      if (serviceProvider.getSamlConfig() != null)
      {
         samlConfiguration = new SamlConfiguration(serviceProvider.getSamlConfig());
      }

      if (serviceProvider.getOpenIdConfig() != null)
      {
         openIdConfiguration = new OpenIdConfiguration(serviceProvider.getOpenIdConfig());
      }
   }

   public String getServiceURL(ExternalAuthenticationService service)
   {
      String path = configuration.getContextRoot() + "/" + service.getName() + ".seam";
      return createURL(path);
   }

   public String getOpenIdRealm()
   {
      return createURL("");
   }

   private String createURL(String path)
   {
      try
      {
         if (protocol.equals("http") && port == 80 || protocol.equals("https") && port == 443)
         {
            return new URL(protocol, hostname, path).toExternalForm();
         }
         else
         {
            return new URL(protocol, hostname, port, path).toExternalForm();
         }
      }
      catch (MalformedURLException e)
      {
         throw new RuntimeException(e);
      }
   }

   public SamlConfiguration getSamlConfiguration()
   {
      return samlConfiguration;
   }

   public OpenIdConfiguration getOpenIdConfiguration()
   {
      return openIdConfiguration;
   }

   public String getHostname()
   {
      return hostname;
   }

   public String getProtocol()
   {
      return protocol;
   }

   public int getPort()
   {
      return port;
   }

   public String getLoggedOutUrl()
   {
      return loggedOutUrl;
   }

   public String getUnsolicitedAuthenticationUrl()
   {
      return unsolicitedAuthenticationUrl;
   }

   public String getFailedAuthenticationUrl()
   {
      return failedAuthenticationUrl;
   }

   public MethodExpression getInternalAuthenticationMethod()
   {
      return internalAuthenticationMethod;
   }
}
