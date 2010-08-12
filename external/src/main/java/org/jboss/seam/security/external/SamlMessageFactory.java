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

import java.util.UUID;

import javax.inject.Inject;
import javax.naming.ConfigurationException;

import org.jboss.seam.security.external.configuration.ServiceProvider;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusCodeType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusType;

public class SamlMessageFactory
{
   @Inject
   private ServiceProvider serviceProvider;

   public StatusResponseType createStatusResponse(RequestAbstractType request, String statusCode, String statusMessage)
   {
      ObjectFactory objectFactory = new ObjectFactory();
      org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory assertionObjectFactory = new org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory();

      StatusResponseType response = objectFactory.createStatusResponseType();

      response.setID(generateId());
      response.setIssueInstant(SamlUtils.getXMLGregorianCalendar());

      NameIDType issuer = assertionObjectFactory.createNameIDType();
      issuer.setValue(serviceProvider.getSamlConfiguration().getEntityId());
      response.setIssuer(issuer);

      response.setVersion(SamlConstants.VERSION_2_0);
      response.setInResponseTo(request.getID());

      StatusCodeType statusCodeJaxb = objectFactory.createStatusCodeType();
      statusCodeJaxb.setValue(statusCode);

      StatusType statusType = objectFactory.createStatusType();
      statusType.setStatusCode(statusCodeJaxb);
      if (statusMessage != null)
      {
         statusType.setStatusMessage(statusMessage);
      }

      response.setStatus(statusType);

      return response;
   }

   public AuthnRequestType createAuthnRequest()
   {
      ObjectFactory objectFactory = new ObjectFactory();
      org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory assertionObjectFactory = new org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory();

      AuthnRequestType authnRequest = objectFactory.createAuthnRequestType();

      authnRequest.setID(generateId());
      authnRequest.setIssueInstant(SamlUtils.getXMLGregorianCalendar());

      NameIDType issuer = assertionObjectFactory.createNameIDType();
      issuer.setValue(serviceProvider.getSamlConfiguration().getEntityId());
      authnRequest.setIssuer(issuer);

      authnRequest.setVersion(SamlConstants.VERSION_2_0);

      // Fill in the optional fields that indicate where and how the response
      // should be delivered.
      authnRequest.setAssertionConsumerServiceURL(serviceProvider.getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));
      authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

      return authnRequest;
   }

   public LogoutRequestType createLogoutRequest(SeamSamlPrincipal principal) throws ConfigurationException
   {
      ObjectFactory objectFactory = new ObjectFactory();
      org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory assertionObjectFactory = new org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory();

      LogoutRequestType logoutRequest = objectFactory.createLogoutRequestType();

      logoutRequest.setID(generateId());
      logoutRequest.setIssueInstant(SamlUtils.getXMLGregorianCalendar());

      NameIDType issuer = assertionObjectFactory.createNameIDType();
      issuer.setValue(serviceProvider.getSamlConfiguration().getEntityId());
      logoutRequest.setIssuer(issuer);

      NameIDType nameID = assertionObjectFactory.createNameIDType();
      nameID.setValue(principal.getNameId().getValue());
      logoutRequest.setNameID(nameID);

      logoutRequest.setVersion(SamlConstants.VERSION_2_0);
      logoutRequest.getSessionIndex().add(principal.getSessionIndex());

      return logoutRequest;
   }

   private String generateId()
   {
      return "ID_" + UUID.randomUUID();
   }
}
