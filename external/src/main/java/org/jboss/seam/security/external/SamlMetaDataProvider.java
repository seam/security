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
package org.jboss.seam.security.external;

import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external.configuration.ServiceProvider;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.EntityDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IndexedEndpointType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.KeyDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.KeyTypes;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.SPSSODescriptorType;
import org.jboss.seam.security.external.jaxb.xmldsig.KeyInfoType;
import org.jboss.seam.security.external.jaxb.xmldsig.X509DataType;

public class SamlMetaDataProvider
{
   @Inject
   private ServiceProvider serviceProvider;

   public void writeMetaData(OutputStream stream)
   {
      try
      {
         ObjectFactory metaDataFactory = new ObjectFactory();

         IndexedEndpointType acsRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
         acsRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
         acsRedirectEndpoint.setLocation(serviceProvider.getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));

         IndexedEndpointType acsPostEndpoint = metaDataFactory.createIndexedEndpointType();
         acsPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
         acsPostEndpoint.setLocation(serviceProvider.getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));

         IndexedEndpointType sloRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
         sloRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
         sloRedirectEndpoint.setLocation(serviceProvider.getServiceURL(ExternalAuthenticationService.SAML_SINGLE_LOGOUT_SERVICE));

         IndexedEndpointType sloPostEndpoint = metaDataFactory.createIndexedEndpointType();
         sloPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
         sloPostEndpoint.setLocation(serviceProvider.getServiceURL(ExternalAuthenticationService.SAML_SINGLE_LOGOUT_SERVICE));

         SPSSODescriptorType spSsoDescriptor = metaDataFactory.createSPSSODescriptorType();
         spSsoDescriptor.setAuthnRequestsSigned(serviceProvider.getSamlConfiguration().isAuthnRequestsSigned());
         spSsoDescriptor.setWantAssertionsSigned(serviceProvider.getSamlConfiguration().isWantAssertionsSigned());

         spSsoDescriptor.getAssertionConsumerService().add(acsRedirectEndpoint);
         spSsoDescriptor.getAssertionConsumerService().add(acsPostEndpoint);
         spSsoDescriptor.getSingleLogoutService().add(sloRedirectEndpoint);
         spSsoDescriptor.getSingleLogoutService().add(sloPostEndpoint);

         spSsoDescriptor.getProtocolSupportEnumeration().add(SamlConstants.PROTOCOL_NSURI);

         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress");

         org.jboss.seam.security.external.jaxb.xmldsig.ObjectFactory signatureFactory = new org.jboss.seam.security.external.jaxb.xmldsig.ObjectFactory();

         X509Certificate certificate = serviceProvider.getSamlConfiguration().getCertificate();
         if (certificate == null)
            throw new RuntimeException("Certificate obtained from configuration is null");

         JAXBElement<byte[]> X509Certificate;
         try
         {
            X509Certificate = signatureFactory.createX509DataTypeX509Certificate(certificate.getEncoded());
         }
         catch (CertificateEncodingException e)
         {
            throw new RuntimeException(e);
         }

         X509DataType X509Data = signatureFactory.createX509DataType();
         X509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(X509Certificate);

         KeyInfoType keyInfo = signatureFactory.createKeyInfoType();
         keyInfo.getContent().add(signatureFactory.createX509Data(X509Data));

         KeyDescriptorType keyDescriptor = metaDataFactory.createKeyDescriptorType();
         keyDescriptor.setUse(KeyTypes.SIGNING);
         keyDescriptor.setKeyInfo(keyInfo);

         spSsoDescriptor.getKeyDescriptor().add(keyDescriptor);

         EntityDescriptorType entityDescriptor = metaDataFactory.createEntityDescriptorType();
         entityDescriptor.setEntityID(serviceProvider.getSamlConfiguration().getEntityId());
         entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(spSsoDescriptor);

         JAXBContext jaxbContext = JAXBContext.newInstance("org.picketlink.identity.federation.saml.v2.metadata");
         Marshaller marshaller = jaxbContext.createMarshaller();
         marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
         marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         marshaller.marshal(metaDataFactory.createEntityDescriptor(entityDescriptor), stream);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }
}
