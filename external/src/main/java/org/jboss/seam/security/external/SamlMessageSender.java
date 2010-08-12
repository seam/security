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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.Binder;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jboss.seam.security.external.configuration.Binding;
import org.jboss.seam.security.external.configuration.SamlEndpoint;
import org.jboss.seam.security.external.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external.configuration.SamlService;
import org.jboss.seam.security.external.configuration.ServiceProvider;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

@Named("org.picketlink.identity.seam.federation.samlMessageSender")
public class SamlMessageSender
{
   private Logger log = LoggerFactory.getLogger(SamlMessageSender.class);

   @Inject
   private ServiceProvider serviceProvider;

   @Inject
   private SamlSignatureUtilForPostBinding signatureUtilForPostBinding;

   @Inject
   private SamlSignatureUtilForRedirectBinding signatureUtilForRedirectBinding;

   private JAXBContext jaxbContextRequestAbstractType;

   private JAXBContext jaxbContextStatusResponseType;

   @Inject
   public void init()
   {
      try
      {
         jaxbContextRequestAbstractType = JAXBContext.newInstance(RequestAbstractType.class);
         jaxbContextStatusResponseType = JAXBContext.newInstance(StatusResponseType.class);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void sendRequestToIDP(HttpServletRequest request, HttpServletResponse response, SamlIdentityProvider samlIdentityProvider, SamlProfile profile, RequestAbstractType samlRequest)
   {
      Document message = null;
      SamlEndpoint endpoint = null;
      try
      {
         SamlService service = samlIdentityProvider.getService(profile);
         endpoint = service.getEndpointForBinding(Binding.HTTP_Post);
         if (endpoint == null)
         {
            endpoint = service.getEndpointForBinding(Binding.HTTP_Redirect);
         }
         if (endpoint == null)
         {
            throw new RuntimeException("Idp " + samlIdentityProvider.getEntityId() + " has no endpoint found for profile " + profile);
         }
         samlRequest.setDestination(endpoint.getLocation());

         JAXBElement<?> requestElement;
         if (samlRequest instanceof AuthnRequestType)
         {
            AuthnRequestType authnRequest = (AuthnRequestType) samlRequest;
            requestElement = new ObjectFactory().createAuthnRequest(authnRequest);
         }
         else if (samlRequest instanceof LogoutRequestType)
         {
            LogoutRequestType logoutRequest = (LogoutRequestType) samlRequest;
            requestElement = new ObjectFactory().createLogoutRequest(logoutRequest);
         }
         else
         {
            throw new RuntimeException("Currently only authentication and logout requests can be sent");
         }

         Binder<Node> binder = jaxbContextRequestAbstractType.createBinder();

         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         factory.setNamespaceAware(true);
         factory.setXIncludeAware(true);
         DocumentBuilder builder;
         builder = factory.newDocumentBuilder();
         message = builder.newDocument();

         binder.marshal(requestElement, message);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      catch (ParserConfigurationException e)
      {
         throw new RuntimeException(e);
      }

      sendMessageToIDP(request, response, samlIdentityProvider, message, RequestOrResponse.REQUEST, endpoint);
   }

   public void sendResponseToIDP(HttpServletRequest request, HttpServletResponse response, SamlIdentityProvider samlIdentityProvider, SamlEndpoint endpoint, StatusResponseType samlResponse)
   {
      Document message = null;
      try
      {
         samlResponse.setDestination(endpoint.getResponseLocation());

         JAXBElement<StatusResponseType> responseElement;
         if (endpoint.getService().getProfile().equals(SamlProfile.SINGLE_LOGOUT))
         {
            responseElement = new ObjectFactory().createLogoutResponse(samlResponse);
         }
         else
         {
            throw new RuntimeException("Responses can currently only be created for the single logout service");
         }

         Binder<Node> binder = jaxbContextStatusResponseType.createBinder();

         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         factory.setNamespaceAware(true);
         factory.setXIncludeAware(true);
         DocumentBuilder builder;
         builder = factory.newDocumentBuilder();
         message = builder.newDocument();

         binder.marshal(responseElement, message);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      catch (ParserConfigurationException e)
      {
         throw new RuntimeException(e);
      }

      sendMessageToIDP(request, response, samlIdentityProvider, message, RequestOrResponse.RESPONSE, endpoint);
   }

   private void sendMessageToIDP(HttpServletRequest request, HttpServletResponse response, SamlIdentityProvider samlIdentityProvider, Document message, RequestOrResponse requestOrResponse, SamlEndpoint endpoint)
   {
      if (log.isDebugEnabled())
      {
         log.debug("Sending over to IDP: " + SamlUtils.getDocumentAsString(message));
      }

      try
      {
         boolean signMessage;
         if (endpoint.getService().getProfile().equals(SamlProfile.SINGLE_SIGN_ON))
         {
            signMessage = samlIdentityProvider.isWantAuthnRequestsSigned();
         }
         else
         {
            signMessage = samlIdentityProvider.isWantSingleLogoutMessagesSigned();
         }

         PrivateKey privateKey = serviceProvider.getSamlConfiguration().getPrivateKey();

         if (endpoint.getBinding() == Binding.HTTP_Redirect)
         {
            byte[] responseBytes = SamlUtils.getDocumentAsString(message).getBytes("UTF-8");

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(baos, deflater);
            deflaterStream.write(responseBytes);
            deflaterStream.finish();

            byte[] deflatedMsg = baos.toByteArray();
            String urlEncodedResponse = Base64.encodeBytes(deflatedMsg);

            String finalDest = endpoint.getLocation() + getQueryString(urlEncodedResponse, signMessage, requestOrResponse, privateKey);
            SamlUtils.sendRedirect(finalDest, response);
         }
         else
         {
            if (signMessage)
            {
               PublicKey publicKey = serviceProvider.getSamlConfiguration().getCertificate().getPublicKey();
               signSAMLDocument(message, new KeyPair(publicKey, privateKey));
            }
            byte[] responseBytes = SamlUtils.getDocumentAsString(message).getBytes("UTF-8");

            String samlResponse = Base64.encodeBytes(responseBytes, Base64.DONT_BREAK_LINES);

            sendPost(endpoint.getLocation(), samlResponse, response, requestOrResponse.isRequest());

         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private void signSAMLDocument(Document samlDocument, KeyPair keypair)
   {
      // Get the ID from the root
      String id = samlDocument.getDocumentElement().getAttribute("ID");

      String referenceURI = "#" + id;

      signatureUtilForPostBinding.sign(samlDocument, keypair, DigestMethod.SHA1, SignatureMethod.RSA_SHA1, referenceURI);
   }

   private String getQueryString(String urlEncodedSamlMessage, boolean supportSignature, RequestOrResponse requestOrResponse, PrivateKey signingKey)
   {
      StringBuilder sb = new StringBuilder();
      sb.append("?");

      if (supportSignature)
      {
         try
         {
            sb.append(getURLWithSignature(requestOrResponse, urlEncodedSamlMessage, signingKey));
         }
         catch (IOException e)
         {
            throw new RuntimeException(e);
         }
         catch (GeneralSecurityException e)
         {
            throw new RuntimeException(e);
         }
      }
      else
      {
         if (requestOrResponse == RequestOrResponse.REQUEST)
         {
            sb.append(SamlConstants.QSP_SAML_REQUEST);
         }
         else
         {
            sb.append(SamlConstants.QSP_SAML_RESPONSE);
         }
         sb.append("=").append(urlEncodedSamlMessage);
      }
      return sb.toString();
   }

   private void sendPost(String destination, String samlMessage, HttpServletResponse response, boolean request) throws IOException
   {
      String key = request ? SamlConstants.QSP_SAML_REQUEST : SamlConstants.QSP_SAML_RESPONSE;

      if (destination == null)
         throw new IllegalStateException("Destination is null");

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      response.setCharacterEncoding("UTF-8");
      response.setHeader("Pragma", "no-cache");
      response.setHeader("Cache-Control", "no-cache, no-store");
      StringBuilder builder = new StringBuilder();

      builder.append("<HTML>");
      builder.append("<HEAD>");
      if (request)
         builder.append("<TITLE>HTTP Post Binding (Request)</TITLE>");
      else
         builder.append("<TITLE>HTTP Post Binding Response (Response)</TITLE>");

      builder.append("</HEAD>");
      builder.append("<BODY Onload=\"document.forms[0].submit()\">");

      builder.append("<FORM METHOD=\"POST\" ACTION=\"" + destination + "\">");
      builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"" + key + "\"" + " VALUE=\"" + samlMessage + "\"/>");
      builder.append("</FORM></BODY></HTML>");

      String str = builder.toString();
      out.println(str);
      out.close();
   }

   private String getURLWithSignature(RequestOrResponse requestOrResponse, String urlEncodedResponse, PrivateKey signingKey) throws IOException, GeneralSecurityException
   {
      String messageParameter;
      if (requestOrResponse == RequestOrResponse.REQUEST)
      {
         messageParameter = SamlConstants.QSP_SAML_REQUEST;
      }
      else
      {
         messageParameter = SamlConstants.QSP_SAML_RESPONSE;
      }

      byte[] signature = signatureUtilForRedirectBinding.computeSignature(messageParameter + "=" + urlEncodedResponse, signingKey);
      String sigAlgo = signingKey.getAlgorithm();

      StringBuilder sb = new StringBuilder();
      sb.append(messageParameter + "=").append(urlEncodedResponse);

      try
      {
         sb.append("&").append(SamlConstants.QSP_SIG_ALG).append("=");
         String sigAlg = signatureUtilForRedirectBinding.getXMLSignatureAlgorithmURI(sigAlgo);
         sb.append(URLEncoder.encode(sigAlg, "UTF-8"));

         sb.append("&").append(SamlConstants.QSP_SIGNATURE).append("=");
         String base64encodedSignature = Base64.encodeBytes(signature, Base64.DONT_BREAK_LINES);
         sb.append(URLEncoder.encode(base64encodedSignature, "UTF-8"));
      }
      catch (UnsupportedEncodingException e)
      {
         throw new RuntimeException(e);
      }

      return sb.toString();
   }
}
