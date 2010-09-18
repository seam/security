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
package org.jboss.seam.security.external.openid;

import java.io.IOException;
import java.io.Writer;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.dialogues.DialogueManager;
import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.spi.OpenIdProviderSpi;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.server.ServerManager;

/**
 * @author Marcel Kolsteren
 * 
 */
public class OpenIdProviderAuthenticationService
{
   @Inject
   private Instance<OpenIdProviderRequest> openIdProviderRequest;

   @Inject
   private Instance<ServerManager> openIdServerManager;

   @Inject
   private Instance<OpenIdProviderSpi> openIdProviderSpi;

   @Inject
   private ResponseHandler responseHandler;

   @Inject
   private DialogueManager dialogueManager;

   @Inject
   private Instance<Dialogue> dialogue;

   @Inject
   private Instance<OpenIdProviderBean> opBean;

   public void handleIncomingMessage(HttpServletRequest httpRequest) throws InvalidRequestException
   {
      ParameterList parameterList = new ParameterList(httpRequest.getParameterMap());

      String mode = parameterList.getParameterValue("openid.mode");

      Message response;

      if ("associate".equals(mode))
      {
         response = openIdServerManager.get().associationResponse(parameterList);
         writeMessageToResponse(response);
      }
      else if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode))
      {
         dialogueManager.beginDialogue();
         String claimedIdentifier = parameterList.getParameterValue("openid.claimed_id");
         String opLocalIdentifier = parameterList.getParameterValue("openid.identity");

         openIdProviderRequest.get().setParameterList(parameterList);
         openIdProviderRequest.get().setClaimedIdentifier(claimedIdentifier);

         MessageExtension ext = null;
         try
         {
            AuthRequest authReq = AuthRequest.createAuthRequest(parameterList, openIdServerManager.get().getRealmVerifier());
            if (authReq.hasExtension(AxMessage.OPENID_NS_AX))
            {
               ext = authReq.getExtension(AxMessage.OPENID_NS_AX);
            }
         }
         catch (MessageException e)
         {
            throw new RuntimeException(e);
         }

         if (ext instanceof FetchRequest)
         {
            FetchRequest fetchRequest = (FetchRequest) ext;

            List<OpenIdRequestedAttribute> requestedAttributes = new LinkedList<OpenIdRequestedAttribute>();
            handleAttributeRequests(fetchRequest, requestedAttributes, false);
            handleAttributeRequests(fetchRequest, requestedAttributes, true);
            openIdProviderRequest.get().setRequestedAttributes(requestedAttributes);
            openIdProviderRequest.get().setFetchRequest(fetchRequest);
         }

         if (claimedIdentifier != null && opLocalIdentifier != null)
         {
            boolean immediate = "checkid_immediate".equals(mode);
            String realm = parameterList.getParameterValue("openid.realm");
            if (realm == null)
            {
               realm = parameterList.getParameterValue("openid.return_to");
            }

            if (opLocalIdentifier.equals(AuthRequest.SELECT_ID))
            {
               openIdProviderSpi.get().authenticate(realm, null, immediate);
            }
            else
            {
               String userName = opBean.get().getUserNameFromOpLocalIdentifier(opLocalIdentifier);
               openIdProviderSpi.get().authenticate(realm, userName, immediate);
            }
         }
         else
         {
            response = DirectError.createDirectError("Invalid request; claimed_id or identity attribute is missing");
            writeMessageToResponse(response);
         }
         dialogueManager.detachDialogue();
      }
      else if ("check_authentication".equals(mode))
      {
         response = openIdServerManager.get().verify(parameterList);
         writeMessageToResponse(response);
      }
      else
      {
         response = DirectError.createDirectError("Unknown request");
         writeMessageToResponse(response);
      }
   }

   private void handleAttributeRequests(FetchRequest fetchRequest, List<OpenIdRequestedAttribute> requestedAttributes, boolean required)
   {
      @SuppressWarnings("unchecked")
      Map<String, String> attributes = fetchRequest.getAttributes(required);

      for (Map.Entry<String, String> entry : attributes.entrySet())
      {
         OpenIdRequestedAttribute requestedAttribute = new OpenIdRequestedAttribute();
         requestedAttribute.setAlias(entry.getKey());
         requestedAttribute.setTypeUri(entry.getValue());
         requestedAttribute.setRequired(required);
         requestedAttribute.setCount(fetchRequest.getCount(entry.getKey()));
         requestedAttributes.add(requestedAttribute);
      }
   }

   public void sendAuthenticationResponse(boolean authenticationSuccesful, Map<String, List<String>> attributeValues)
   {
      ParameterList parameterList = openIdProviderRequest.get().getParameterList();
      String userName = openIdProviderRequest.get().getUserName();
      String opLocalIdentifier = opBean.get().getOpLocalIdentifierForUserName(userName);
      String claimedIdentifier = openIdProviderRequest.get().getClaimedIdentifier();
      if (claimedIdentifier.equals(AuthRequest.SELECT_ID))
      {
         claimedIdentifier = opLocalIdentifier;
      }

      Message response = openIdServerManager.get().authResponse(parameterList, opLocalIdentifier, claimedIdentifier, authenticationSuccesful);

      if (response instanceof DirectError)
      {
         writeMessageToResponse(response);
      }
      else
      {
         if (openIdProviderRequest.get().getRequestedAttributes() != null)
         {
            try
            {
               FetchResponse fetchResponse = FetchResponse.createFetchResponse(openIdProviderRequest.get().getFetchRequest(), attributeValues);
               response.addExtension(fetchResponse);
            }
            catch (MessageException e)
            {
               throw new RuntimeException(e);
            }
         }

         // caller will need to decide which of the following to use:

         // option1: GET HTTP-redirect to the return_to URL
         String destinationUrl = response.getDestinationUrl(true);
         responseHandler.sendHttpRedirectToUserAgent(destinationUrl);

         // option2: HTML FORM Redirection
         // RequestDispatcher dispatcher =
         // getServletContext().getRequestDispatcher("formredirection.jsp");
         // httpReq.setAttribute("prameterMap", response.getParameterMap());
         // httpReq.setAttribute("destinationUrl",
         // response.getDestinationUrl(false));
         // dispatcher.forward(request, response);
         // return null;
      }

      dialogue.get().setFinished(true);
   }

   private void writeMessageToResponse(Message message)
   {
      Writer writer = responseHandler.getWriter("text/plain");
      try
      {
         writer.append(message.keyValueFormEncoding());
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }
}
