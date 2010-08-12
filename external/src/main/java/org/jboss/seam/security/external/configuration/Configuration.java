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

import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.jboss.seam.security.external.jaxb.config.ExternalAuthenticationConfigType;
import org.jboss.seam.security.external.jaxb.config.ServiceProviderType;
import org.xml.sax.SAXException;

@Named("configuration")
@ApplicationScoped
// FIXME @Startup
public class Configuration
{
   private final static String CONFIGURATION_FILE = "/external-authentication-config.xml";

   private String contextRoot;

   private Map<String, ServiceProvider> serviceProviderMap = new HashMap<String, ServiceProvider>();

   @Inject
   public void init()
   {
      List<ServiceProvider> serviceProviders = new LinkedList<ServiceProvider>();
      ExternalAuthenticationConfigType externalAuthenticationConfig = readConfigurationFile();
      for (ServiceProviderType serviceProvider : externalAuthenticationConfig.getServiceProvider())
      {
         serviceProviders.add(new ServiceProvider(this, serviceProvider));
      }

      for (ServiceProvider sp : serviceProviders)
      {
         if (serviceProviderMap.containsKey(sp.getHostname()))
         {
            throw new RuntimeException("Two service providers have the same hostname");
         }
         serviceProviderMap.put(sp.getHostname(), sp);
      }
   }

   private ExternalAuthenticationConfigType readConfigurationFile()
   {
      ExternalAuthenticationConfigType externalAuthenticationConfig;
      try
      {
         JAXBContext jaxbContext = JAXBContext.newInstance("org.jboss.seam.security.external.jaxb.config");
         Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
         URL schemaURL = getClass().getResource("/schema/config/external-authentication-config.xsd");
         Schema schema;
         try
         {
            schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(schemaURL);
         }
         catch (SAXException e)
         {
            throw new RuntimeException(e);
         }
         unmarshaller.setSchema(schema);

         JAXBElement<?> o = (JAXBElement<?>) unmarshaller.unmarshal(getClass().getResource(CONFIGURATION_FILE));
         externalAuthenticationConfig = (ExternalAuthenticationConfigType) o.getValue();
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      return externalAuthenticationConfig;
   }

   public void setContextRoot(String contextRoot)
   {
      this.contextRoot = contextRoot;
   }

   public String getContextRoot()
   {
      return contextRoot;
   }

   // FIXME @Factory(scope = ScopeType.EVENT, autoCreate = true, value =
   // "org.jboss.seam.security.external_authentication.serviceProvider")
   public ServiceProvider getServiceProvider()
   {
      String hostname = null; // FIXME =
      // ServletContexts.instance().getRequest().getServerName();
      ;
      return serviceProviderMap.get(hostname);
   }

   public ServiceProvider getServiceProvider(String hostname)
   {
      return serviceProviderMap.get(hostname);
   }
}
