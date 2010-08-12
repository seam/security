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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jboss.seam.security.external_authentication.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external_authentication.configuration.ServiceProvider;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class SamlMessageReceiver
{
   private static final Logger log = LoggerFactory.getLogger(SamlMessageReceiver.class);

   @Inject
   private Requests requests;

   @Inject
   private SamlSingleLogoutReceiver samlSingleLogoutReceiver;

   @Inject
   private SamlSingleSignOnReceiver samlSingleSignOnReceiver;

   @Inject
   private ServiceProvider serviceProvider;

   @Inject
   private SamlSignatureUtilForPostBinding signatureUtilForPostBinding;

   @Inject
   private SamlSignatureUtilForRedirectBinding signatureUtilForRedirectBinding;

   private JAXBContext jaxbContext;

   @Inject
   public void init()
   {
      try
      {
         jaxbContext = JAXBContext.newInstance(StatusResponseType.class);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void handleIncomingSamlMessage(SamlProfile samlProfile, HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws InvalidRequestException
   {
      String samlRequestParam = httpRequest.getParameter(SamlConstants.QSP_SAML_REQUEST);
      String samlResponseParam = httpRequest.getParameter(SamlConstants.QSP_SAML_RESPONSE);

      RequestOrResponse requestOrResponse;
      String samlMessage;

      if (samlRequestParam != null && samlResponseParam == null)
      {
         samlMessage = samlRequestParam;
         requestOrResponse = RequestOrResponse.REQUEST;
      }
      else if (samlRequestParam == null && samlResponseParam != null)
      {
         samlMessage = samlResponseParam;
         requestOrResponse = RequestOrResponse.RESPONSE;
      }
      else
      {
         throw new InvalidRequestException("SAML message should either have a SAMLRequest parameter or a SAMLResponse parameter");
      }

      InputStream is;
      if (httpRequest.getMethod().equals("POST"))
      {
         byte[] decodedMessage = Base64.decode(samlMessage);
         is = new ByteArrayInputStream(decodedMessage);
      }
      else
      {
         String urlDecoded;
         try
         {
            urlDecoded = URLDecoder.decode(samlMessage, "UTF-8");
         }
         catch (UnsupportedEncodingException e)
         {
            throw new RuntimeException(e);
         }
         byte[] base64Decoded = Base64.decode(urlDecoded);
         ByteArrayInputStream bais = new ByteArrayInputStream(base64Decoded);
         is = new InflaterInputStream(bais, new Inflater(true));
      }

      Document document = getDocument(is);
      String issuerEntityId;
      RequestAbstractType samlRequest = null;
      StatusResponseType samlResponse = null;
      if (requestOrResponse.isRequest())
      {
         samlRequest = getSamlRequest(document);
         issuerEntityId = samlRequest.getIssuer().getValue();
      }
      else
      {
         samlResponse = getSamlResponse(document);
         issuerEntityId = samlResponse.getIssuer().getValue();
      }
      if (log.isDebugEnabled())
      {
         log.debug("Received from IDP: " + SamlUtils.getDocumentAsString(document));
      }

      SamlIdentityProvider idp = serviceProvider.getSamlConfiguration().getSamlIdentityProviderByEntityId(issuerEntityId);
      if (idp == null)
      {
         throw new InvalidRequestException("Received message from unknown idp " + issuerEntityId);
      }

      boolean validate;
      if (samlProfile == SamlProfile.SINGLE_SIGN_ON)
      {
         validate = serviceProvider.getSamlConfiguration().isWantAssertionsSigned();
      }
      else
      {
         validate = idp.isSingleLogoutMessagesSigned();
      }

      if (validate)
      {
         if (log.isDebugEnabled())
         {
            log.debug("Validating the signature");
         }
         if (httpRequest.getMethod().equals("POST"))
         {
            signatureUtilForPostBinding.validateSignature(idp, document);
         }
         else
         {
            signatureUtilForRedirectBinding.validateSignature(idp, httpRequest, requestOrResponse);
         }
      }

      RequestContext requestContext = null;
      if (requestOrResponse.isResponse() && samlResponse.getInResponseTo() != null)
      {
         requestContext = requests.getRequest(samlResponse.getInResponseTo());
         if (requestContext == null)
         {
            throw new InvalidRequestException("No request that corresponds with the received response");
         }
         else if (!(requestContext.getIdentityProvider().equals(idp)))
         {
            throw new InvalidRequestException("Identity provider of request and response do not match");
         }
      }

      if (samlProfile == SamlProfile.SINGLE_SIGN_ON)
      {
         if (requestOrResponse.isRequest())
         {
            throw new InvalidRequestException("Assertion consumer service can only process SAML responses");
         }
         else
         {
            samlSingleSignOnReceiver.processIDPResponse(httpRequest, httpResponse, samlResponse, requestContext, idp);
         }
      }
      else
      {
         if (requestOrResponse.isRequest())
         {
            samlSingleLogoutReceiver.processIDPRequest(httpRequest, httpResponse, samlRequest, idp);
         }
         else
         {
            samlSingleLogoutReceiver.processIDPResponse(httpRequest, httpResponse, samlResponse, requestContext, idp);
         }
      }
   }

   private RequestAbstractType getSamlRequest(Document document) throws InvalidRequestException
   {
      try
      {
         Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
         @SuppressWarnings("unchecked")
         JAXBElement<RequestAbstractType> jaxbRequest = (JAXBElement<RequestAbstractType>) unmarshaller.unmarshal(document);
         RequestAbstractType request = jaxbRequest.getValue();
         return request;
      }
      catch (JAXBException e)
      {
         throw new InvalidRequestException("SAML message could not be parsed", e);
      }
   }

   private StatusResponseType getSamlResponse(Document document) throws InvalidRequestException
   {
      try
      {
         Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
         @SuppressWarnings("unchecked")
         JAXBElement<StatusResponseType> jaxbResponseType = (JAXBElement<StatusResponseType>) unmarshaller.unmarshal(document);
         StatusResponseType statusResponse = jaxbResponseType.getValue();
         return statusResponse;
      }
      catch (JAXBException e)
      {
         throw new InvalidRequestException("SAML message could not be parsed", e);
      }
   }

   private Document getDocument(InputStream is) throws InvalidRequestException
   {
      try
      {
         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         factory.setNamespaceAware(true);
         factory.setXIncludeAware(true);
         DocumentBuilder builder = factory.newDocumentBuilder();
         return builder.parse(is);
      }
      catch (ParserConfigurationException e)
      {
         throw new RuntimeException(e);
      }
      catch (SAXException e)
      {
         throw new InvalidRequestException("SAML request could not be parsed", e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }
}
