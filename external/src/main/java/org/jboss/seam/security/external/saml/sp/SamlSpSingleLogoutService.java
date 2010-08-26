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
package org.jboss.seam.security.external.saml.sp;

import java.util.List;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.api.SamlNameId;
import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlMessageFactory;
import org.jboss.seam.security.external.saml.SamlMessageSender;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlSpSingleLogoutService
{
   @Inject
   private SamlMessageFactory samlMessageFactory;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private SamlSpSessions samlSpSessions;

   @Inject
   private Instance<SamlServiceProviderSpi> samlServiceProviderSpi;

   @Inject
   private SamlSpLogoutDialogue samlSpLogoutDialogue;

   @Inject
   private Dialogue dialogue;

   @Inject
   private SamlDialogue samlDialogue;

   public void processIDPRequest(HttpServletRequest httpRequest, RequestAbstractType request) throws InvalidRequestException
   {
      if (!(request instanceof LogoutRequestType))
      {
         throw new InvalidRequestException("Request should be a single logout request.");
      }

      LogoutRequestType logoutRequest = (LogoutRequestType) request;
      SamlExternalIdentityProvider idp = (SamlExternalIdentityProvider) samlDialogue.getExternalProvider();

      NameIDType nameIdJaxb = logoutRequest.getNameID();
      SamlNameId samlNameId = new SamlNameId(nameIdJaxb.getValue(), nameIdJaxb.getFormat(), nameIdJaxb.getNameQualifier());
      removeSessions(samlNameId, idp.getEntityId(), logoutRequest.getSessionIndex());

      StatusResponseType response = samlMessageFactory.createStatusResponse(SamlConstants.STATUS_SUCCESS, null);

      samlMessageSender.sendResponse(idp, response, SamlProfile.SINGLE_LOGOUT);

      dialogue.setFinished(true);
   }

   private void removeSessions(SamlNameId nameId, String idpEntityId, List<String> sessionIndexes)
   {
      for (SamlSpSession session : samlSpSessions.getSessions())
      {
         if (session.getPrincipal().getNameId().equals(nameId) && session.getIdentityProvider().getEntityId().equals(idpEntityId))
         {
            if (sessionIndexes.size() == 0 || sessionIndexes.contains(session.getSessionIndex()))
            {
               samlSpSessions.removeSession(session);
               samlServiceProviderSpi.get().loggedOut(session);
            }
         }
      }
   }

   public void processIDPResponse(HttpServletRequest httpRequest, StatusResponseType response)
   {
      if (response.getStatus() != null && response.getStatus().getStatusCode().getValue().equals(SamlConstants.STATUS_SUCCESS))
      {
         samlServiceProviderSpi.get().singleLogoutSucceeded();
      }
      else
      {
         String statusCode = response.getStatus() == null ? "null" : response.getStatus().getStatusCode().getValue();
         samlServiceProviderSpi.get().singleLogoutFailed(statusCode);
      }
      dialogue.setFinished(true);
   }

   public void sendSingleLogoutRequestToIDP(SamlSpSession session)
   {
      SamlExternalIdentityProvider idp = session.getIdentityProvider();
      LogoutRequestType logoutRequest;
      logoutRequest = samlMessageFactory.createLogoutRequest(session.getPrincipal().getNameId(), session.getSessionIndex());

      samlDialogue.setExternalProvider(idp);
      samlSpLogoutDialogue.setSession(session);

      samlMessageSender.sendRequest(idp, SamlProfile.SINGLE_LOGOUT, logoutRequest);
   }
}
