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
package org.jboss.seam.security.external.saml.idp;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.DialogueBean;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlEntityBean;
import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.SamlMessageFactory;
import org.jboss.seam.security.external.saml.SamlMessageSender;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.saml.SamlService;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.sp.SamlExternalIdentityProvider;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlIdpSingleSignOnService
{
   @Inject
   private SamlMessageFactory samlMessageFactory;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private Instance<SamlIdentityProviderSpi> samlIdentityProviderSpi;

   @Inject
   private DialogueBean dialogue;

   @Inject
   private SamlDialogue samlDialogue;

   @Inject
   private Instance<SamlEntityBean> samlEntityBean;

   @Inject
   private ResponseHandler responseHandler;

   public void processSPRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, RequestAbstractType request) throws InvalidRequestException
   {
      if (!(request instanceof AuthnRequestType))
      {
         throw new InvalidRequestException("Request should be an authentication request.");
      }

      samlIdentityProviderSpi.get().authenticate(responseHandler.createResponseHolder(httpResponse));
   }

   public void handleSucceededAuthentication(SamlIdpSession session, HttpServletResponse response)
   {
      sendAuthenticationResponse(samlDialogue.getExternalProvider(), session, false, response);
   }

   private void sendAuthenticationResponse(SamlExternalEntity serviceProvider, SamlIdpSession session, boolean failed, HttpServletResponse response)
   {
      StatusResponseType statusResponse;

      if (failed)
      {
         statusResponse = samlMessageFactory.createStatusResponse(SamlConstants.STATUS_RESPONDER, null);
      }
      else
      {
         SamlService service = serviceProvider.getService(SamlProfile.SINGLE_SIGN_ON);
         statusResponse = samlMessageFactory.createResponse(session, samlMessageSender.getEndpoint(service));
      }

      samlMessageSender.sendResponse(serviceProvider, statusResponse, SamlProfile.SINGLE_SIGN_ON, response);

      dialogue.setFinished(true);
   }

   public void handleFailedAuthentication(HttpServletResponse response)
   {
      sendAuthenticationResponse(samlDialogue.getExternalProvider(), null, true, response);
   }

   @Dialogued
   public void sendAuthenticationResponseToIDP(SamlExternalIdentityProvider idp, HttpServletResponse response)
   {
      AuthnRequestType authnRequest = samlMessageFactory.createAuthnRequest();

      samlDialogue.setExternalProvider(idp);

      samlMessageSender.sendRequest(idp, SamlProfile.SINGLE_SIGN_ON, authnRequest, response);
   }

   public void remoteLogin(String spEntityId, SamlIdpSession session, String remoteUrl, HttpServletResponse response)
   {
      SamlExternalEntity serviceProvider = samlEntityBean.get().getExternalSamlEntityByEntityId(spEntityId);
      samlDialogue.setExternalProvider(serviceProvider);
      samlDialogue.setExternalProviderRelayState(remoteUrl);

      // Send an unsolicited authentication response to the service provider
      sendAuthenticationResponse(serviceProvider, session, false, response);
   }
}
