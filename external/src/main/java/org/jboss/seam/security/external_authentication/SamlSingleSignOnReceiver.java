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

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConstants;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.events.LoginFailedEvent;
import org.jboss.seam.security.events.PostAuthenticateEvent;
import org.jboss.seam.security.external_authentication.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external_authentication.configuration.ServiceProvider;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.AssertionType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.AttributeStatementType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.AuthnStatementType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.StatementAbstractType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.SubjectConfirmationDataType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.assertion.SubjectConfirmationType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.ResponseType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.StatusType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlSingleSignOnReceiver
{
   private Logger log = LoggerFactory.getLogger(SamlSingleSignOnReceiver.class);

   @Inject
   private Requests requests;

   @Inject
   private Identity identity;

   @Inject
   private InternalAuthenticator internalAuthenticator;

   @Inject
   private ServiceProvider serviceProvider;

   @Inject
   private BeanManager beanManager;

   public void processIDPResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse, StatusResponseType statusResponse, RequestContext requestContext, SamlIdentityProvider idp) throws InvalidRequestException
   {
      StatusType status = statusResponse.getStatus();
      if (status == null)
      {
         throw new InvalidRequestException("Response does not contain a status");
      }

      String statusValue = status.getStatusCode().getValue();
      if (SamlConstants.STATUS_SUCCESS.equals(statusValue) == false)
      {
         throw new RuntimeException("IDP returned status " + statusValue);
      }

      if (!(statusResponse instanceof ResponseType))
      {
         throw new InvalidRequestException("Response does not have type ResponseType");
      }

      ResponseType response = (ResponseType) statusResponse;

      List<Object> assertions = response.getAssertionOrEncryptedAssertion();
      if (assertions.size() == 0)
      {
         throw new RuntimeException("IDP response does not contain assertions");
      }

      SeamSamlPrincipal principal = getAuthenticatedUser(response, requestContext);
      if (principal == null)
      {
         try
         {
            beanManager.fireEvent(new PostAuthenticateEvent());
            beanManager.fireEvent(new LoginFailedEvent(new LoginException()));

            httpResponse.sendRedirect(serviceProvider.getFailedAuthenticationUrl());
         }
         catch (IOException e)
         {
            throw new RuntimeException(e);
         }
      }
      else
      {
         // Login the user, and redirect to the requested page.
         principal.setIdentityProvider(idp);
         loginUser(httpRequest, httpResponse, principal, requestContext);
      }
   }

   private SeamSamlPrincipal getAuthenticatedUser(ResponseType responseType, RequestContext requestContext)
   {
      SeamSamlPrincipal principal = null;

      for (Object assertion : responseType.getAssertionOrEncryptedAssertion())
      {
         if (assertion instanceof AssertionType)
         {
            SeamSamlPrincipal assertionSubject = handleAssertion((AssertionType) assertion, requestContext);
            if (principal == null)
            {
               principal = assertionSubject;
            }
            else
            {
               log.warn("Multiple authenticated users found in assertions. Using the first one.");
            }
         }
         else
         {
            /* assertion instanceof EncryptedElementType */
            log.warn("Encountered encrypted assertion. Skipping it because decryption is not yet supported.");
         }
      }
      return principal;
   }

   private SeamSamlPrincipal handleAssertion(AssertionType assertion, RequestContext requestContext)
   {
      if (SamlUtils.hasAssertionExpired(assertion))
      {
         log.warn("Received assertion not processed because it has expired.");
         return null;
      }

      AuthnStatementType authnStatement = extractValidAuthnStatement(assertion);
      if (authnStatement == null)
      {
         log.warn("Received assertion not processed because it doesn't contain a valid authnStatement.");
         return null;
      }

      NameIDType nameId = validateSubjectAndExtractNameID(assertion, requestContext);
      if (nameId == null)
      {
         log.warn("Received assertion not processed because it doesn't contain a valid subject.");
         return null;
      }

      SeamSamlPrincipal principal = new SeamSamlPrincipal();
      principal.setAssertion(assertion);
      principal.setSessionIndex(authnStatement.getSessionIndex());
      principal.setNameId(nameId);

      for (StatementAbstractType statement : assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement())
      {
         if (statement instanceof AttributeStatementType)
         {
            AttributeStatementType attributeStatement = (AttributeStatementType) statement;
            List<AttributeType> attributes = new LinkedList<AttributeType>();
            for (Object object : attributeStatement.getAttributeOrEncryptedAttribute())
            {
               if (object instanceof AttributeType)
               {
                  attributes.add((AttributeType) object);
               }
               else
               {
                  log.warn("Encrypted attributes are not supported. Ignoring the attribute.");
               }
            }
            principal.setAttributes(attributes);
         }
      }

      return principal;
   }

   private AuthnStatementType extractValidAuthnStatement(AssertionType assertion)
   {
      for (StatementAbstractType statement : assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement())
      {
         if (statement instanceof AuthnStatementType)
         {
            AuthnStatementType authnStatement = (AuthnStatementType) statement;
            return authnStatement;
         }
      }

      return null;
   }

   private NameIDType validateSubjectAndExtractNameID(AssertionType assertion, RequestContext requestContext)
   {
      NameIDType nameId = null;
      boolean validConfirmationFound = false;

      for (JAXBElement<?> contentElement : assertion.getSubject().getContent())
      {
         if (contentElement.getValue() instanceof NameIDType)
         {
            nameId = (NameIDType) contentElement.getValue();
         }
         if (contentElement.getValue() instanceof SubjectConfirmationType)
         {
            SubjectConfirmationType confirmation = (SubjectConfirmationType) contentElement.getValue();
            if (confirmation.getMethod().equals(SamlConstants.CONFIRMATION_METHOD_BEARER))
            {
               SubjectConfirmationDataType confirmationData = confirmation.getSubjectConfirmationData();

               boolean validRecipient = confirmationData.getRecipient().equals(serviceProvider.getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));

               boolean notTooLate = confirmationData.getNotOnOrAfter().compare(SamlUtils.getXMLGregorianCalendar()) == DatatypeConstants.GREATER;

               boolean validInResponseTo = requestContext == null || confirmationData.getInResponseTo().equals(requestContext.getId());

               if (validRecipient && notTooLate && validInResponseTo)
               {
                  validConfirmationFound = true;
               }
            }
         }
      }

      if (validConfirmationFound)
      {
         return nameId;
      }
      else
      {
         return null;
      }
   }

   private void loginUser(HttpServletRequest httpRequest, HttpServletResponse httpResponse, SeamSamlPrincipal principal, RequestContext requestContext)
   {
      if (identity.isLoggedIn())
      {
         throw new RuntimeException("User is already logged in.");
      }

      boolean internallyAuthenticated = internalAuthenticator.authenticate(principal, httpRequest);

      try
      {
         if (internallyAuthenticated)
         {
            if (requestContext == null)
            {
               redirectForUnsolicitedAuthentication(httpRequest, httpResponse);
            }
            else
            {
               requests.redirect(requestContext.getId(), httpResponse);
            }
         }
         else
         {
            httpResponse.sendRedirect(serviceProvider.getFailedAuthenticationUrl());
         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private void redirectForUnsolicitedAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
   {
      String relayState = httpRequest.getParameter("RelayState");

      /* Unsolicited authentication. */

      if (relayState != null)
      {
         httpResponse.sendRedirect(relayState);
      }
      else
      {
         String unsolicitedAuthenticationUrl = serviceProvider.getUnsolicitedAuthenticationUrl();
         if (unsolicitedAuthenticationUrl != null)
         {
            httpResponse.sendRedirect(unsolicitedAuthenticationUrl);
         }
         else
         {
            throw new RuntimeException("Unsolicited login could not be handled because the unsolicitedAuthenticationViewId property has not been configured");
         }
      }
   }
}
