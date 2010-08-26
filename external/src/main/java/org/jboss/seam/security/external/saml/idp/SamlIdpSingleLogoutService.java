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

import java.util.List;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.api.SamlNameId;
import org.jboss.seam.security.external.api.SamlPrincipal;
import org.jboss.seam.security.external.dialogues.DialogueManager;
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
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlIdpSingleLogoutService
{
   @Inject
   private SamlMessageFactory samlMessageFactory;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private SamlIdpSessions samlIdpSessions;

   @Inject
   private Instance<SamlIdentityProviderSpi> samlIdentityProviderSpi;

   @Inject
   private Instance<Dialogue> dialogue;

   @Inject
   private Instance<SamlDialogue> samlDialogue;

   @Inject
   private Instance<SamlIdpIncomingLogoutDialogue> samlIdpIncomingLogoutDialogue;

   @Inject
   private Instance<SamlIdpOutgoingLogoutDialogue> samlIdpOutgoingLogoutDialogue;

   @Inject
   private DialogueManager dialogueManager;

   public void processSPRequest(HttpServletRequest httpRequest, RequestAbstractType request) throws InvalidRequestException
   {
      if (!(request instanceof LogoutRequestType))
      {
         throw new InvalidRequestException("Request should be a single logout request.");
      }

      LogoutRequestType logoutRequest = (LogoutRequestType) request;

      NameIDType nameIdJaxb = logoutRequest.getNameID();
      SamlNameId samlNameId = new SamlNameId(nameIdJaxb.getValue(), nameIdJaxb.getFormat(), nameIdJaxb.getNameQualifier());

      samlIdpIncomingLogoutDialogue.get().setNameId(samlNameId);
      samlIdpIncomingLogoutDialogue.get().setSessionIndexes(logoutRequest.getSessionIndex());

      removeNextSessionParticipant();
   }

   public void handleIDPInitiatedSingleLogout(SamlPrincipal principal, List<String> indexes)
   {
      samlIdpIncomingLogoutDialogue.get().setNameId(principal.getNameId());
      samlIdpIncomingLogoutDialogue.get().setSessionIndexes(indexes);

      removeNextSessionParticipant();
   }

   private void removeNextSessionParticipant()
   {
      SamlNameId samlNameId = samlIdpIncomingLogoutDialogue.get().getNameId();
      List<String> sessionIndexes = samlIdpIncomingLogoutDialogue.get().getSessionIndexes();

      boolean readyForNow = false;

      while (!readyForNow)
      {
         // Find the next session that matches with the removal criteria and
         // that has not been removed yet.
         SamlIdpSession sessionToRemove = null;
         for (SamlIdpSession session : samlIdpSessions.getSessions())
         {
            if (session.getPrincipal().getNameId().equals(samlNameId))
            {
               if (sessionIndexes == null || sessionIndexes.size() == 0 || sessionIndexes.contains(session.getSessionIndex()))
               {
                  sessionToRemove = session;
                  break;
               }
            }
         }

         if (sessionToRemove != null)
         {
            // For the session that is about to be removed, get the first
            // service provider that participates in the session. Remove it from
            // the session.
            SamlExternalServiceProvider sp = sessionToRemove.getServiceProviders().iterator().next();
            sessionToRemove.getServiceProviders().remove(sp);
            if (sessionToRemove.getServiceProviders().size() == 0)
            {
               samlIdpSessions.removeSession(sessionToRemove);
               if (samlDialogue.get().getExternalProvider() != null)
               {
                  samlIdentityProviderSpi.get().loggedOut(sessionToRemove);
               }
            }

            // If the session participant is not the party that initiated the
            // single logout, and it has a single logout service, send a
            // single logout request. Otherwise, move on to the next session
            // participant (if available) or to the next session.
            if (!sp.equals(samlDialogue.get().getExternalProvider()) && sp.getService(SamlProfile.SINGLE_LOGOUT) != null)
            {
               String incomingDialogueId = dialogue.get().getDialogueId();
               dialogueManager.detachDialogue();
               dialogueManager.beginDialogue();
               samlIdpOutgoingLogoutDialogue.get().setIncomingDialogueId(incomingDialogueId);

               sendSingleLogoutRequestToSP(sessionToRemove, sp);
               readyForNow = true;
            }
         }
         else
         {
            finishSingleLogoutProcess();
            readyForNow = true;
         }
      }
   }

   private void finishSingleLogoutProcess()
   {
      boolean failed = samlIdpIncomingLogoutDialogue.get().isFailed();
      if (samlDialogue.get().getExternalProvider() != null)
      {
         StatusResponseType response = samlMessageFactory.createStatusResponse(failed ? SamlConstants.STATUS_RESPONDER : SamlConstants.STATUS_SUCCESS, null);
         samlMessageSender.sendResponse(samlDialogue.get().getExternalProvider(), response, SamlProfile.SINGLE_LOGOUT);
      }
      else
      {
         if (failed)
         {
            samlIdentityProviderSpi.get().singleLogoutFailed();
         }
         else
         {
            samlIdentityProviderSpi.get().singleLogoutSucceeded();
         }
      }
      dialogue.get().setFinished(true);
   }

   public void processSPResponse(HttpServletRequest httpRequest, StatusResponseType response)
   {
      // End the outgoing samlDialogue and re-attach to the incoming
      // samlDialogue
      String incomingDialogueId = samlIdpOutgoingLogoutDialogue.get().getIncomingDialogueId();
      dialogueManager.endDialogue();
      dialogueManager.attachDialogue(incomingDialogueId);

      if (response.getStatus() != null && !response.getStatus().getStatusCode().getValue().equals(SamlConstants.STATUS_SUCCESS))
      {
         samlIdpIncomingLogoutDialogue.get().setFailed(true);
      }

      removeNextSessionParticipant();
   }

   public void sendSingleLogoutRequestToSP(SamlIdpSession session, SamlExternalServiceProvider sp)
   {
      LogoutRequestType logoutRequest;
      logoutRequest = samlMessageFactory.createLogoutRequest(session.getPrincipal().getNameId(), session.getSessionIndex());
      samlDialogue.get().setExternalProvider(sp);

      samlMessageSender.sendRequest(sp, SamlProfile.SINGLE_LOGOUT, logoutRequest);
   }
}
