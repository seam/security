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
package org.jboss.seam.security.external_authentication;

import java.io.OutputStream;

import javax.inject.Inject;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external_authentication.configuration.ServiceProvider;
import org.jboss.seam.security.external_authentication.jaxb.xrds.ObjectFactory;
import org.jboss.seam.security.external_authentication.jaxb.xrds.Service;
import org.jboss.seam.security.external_authentication.jaxb.xrds.Type;
import org.jboss.seam.security.external_authentication.jaxb.xrds.URIPriorityAppendPattern;
import org.jboss.seam.security.external_authentication.jaxb.xrds.XRD;
import org.jboss.seam.security.external_authentication.jaxb.xrds.XRDS;
import org.openid4java.discovery.DiscoveryInformation;

public class OpenIdXrdsProvider
{
   @Inject
   private ServiceProvider serviceProvider;

   public void writeMetaData(OutputStream stream)
   {
      try
      {
         ObjectFactory objectFactory = new ObjectFactory();

         XRDS xrds = objectFactory.createXRDS();

         XRD xrd = objectFactory.createXRD();

         Type type = objectFactory.createType();
         type.setValue(DiscoveryInformation.OPENID2_RP);
         URIPriorityAppendPattern uri = objectFactory.createURIPriorityAppendPattern();
         uri.setValue(serviceProvider.getServiceURL(ExternalAuthenticationService.OPEN_ID_SERVICE));

         Service service = objectFactory.createService();
         service.getType().add(type);
         service.getURI().add(uri);

         xrd.getService().add(service);

         xrds.getOtherelement().add(xrd);

         JAXBContext jaxbContext = JAXBContext.newInstance("org.jboss.seam.security.external_authentication.jaxb.xrds");
         Marshaller marshaller = jaxbContext.createMarshaller();
         marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
         marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         marshaller.marshal(xrds, stream);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }
}
