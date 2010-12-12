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

import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.OpenIdPrincipalImpl;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.DialogueBean;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.spi.OpenIdRelyingPartySpi;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;

/**
 * @author Marcel Kolsteren
 * 
 */
public class OpenIdRpAuthenticationService
{
   @Inject
   private OpenIdRequest openIdRequest;

   @Inject
   private ConsumerManager openIdConsumerManager;

   @Inject
   private Instance<OpenIdRelyingPartySpi> openIdRelyingPartySpi;

   @Inject
   private OpenIdRpBean relyingPartyBean;

   @Inject
   private ResponseHandler responseHandler;

   @Inject
   private Logger log;

   @Inject
   private Instance<DialogueBean> dialogue;

   public void handleIncomingMessage(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws InvalidRequestException
   {
      try
      {
         // extract the parameters from the authentication response
         // (which comes in as a HTTP request from the OpenID provider)
         ParameterList parameterList = new ParameterList(httpRequest.getParameterMap());

         // retrieve the previously stored discovery information
         DiscoveryInformation discovered = openIdRequest.getDiscoveryInformation();

         // extract the receiving URL from the HTTP request
         StringBuffer receivingURL = httpRequest.getRequestURL();
         String queryString = httpRequest.getQueryString();
         if (queryString != null && queryString.length() > 0)
            receivingURL.append("?").append(httpRequest.getQueryString());

         // verify the response; ConsumerManager needs to be the same
         // (static) instance used to place the authentication request
         VerificationResult verification = openIdConsumerManager.verify(receivingURL.toString(), parameterList, discovered);

         // examine the verification result and extract the verified identifier
         Identifier identifier = verification.getVerifiedId();

         if (identifier != null)
         {
            AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();

            Map<String, List<String>> attributeValues = null;
            if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX))
            {
               FetchResponse fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);
               @SuppressWarnings("unchecked")
               Map<String, List<String>> attrValues = fetchResp.getAttributes();
               attributeValues = attrValues;
            }

            OpenIdPrincipal principal = createPrincipal(identifier.getIdentifier(), discovered.getOPEndpoint(), attributeValues);

            openIdRelyingPartySpi.get().loginSucceeded(principal, responseHandler.createResponseHolder(httpResponse));
         }
         else
         {
            openIdRelyingPartySpi.get().loginFailed(verification.getStatusMsg(), responseHandler.createResponseHolder(httpResponse));
         }
      }
      catch (OpenIDException e)
      {
         responseHandler.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage(), httpResponse);
         return;
      }

      dialogue.get().setFinished(true);
   }

   @Dialogued(join = true)
   public void sendAuthRequest(String openId, List<OpenIdRequestedAttribute> attributes, HttpServletResponse response)
   {
      try
      {
         @SuppressWarnings("unchecked")
         List<DiscoveryInformation> discoveries = openIdConsumerManager.discover(openId);

         DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);

         openIdRequest.setDiscoveryInformation(discovered);

         String openIdServiceUrl = relyingPartyBean.getServiceURL(OpenIdService.OPEN_ID_SERVICE);
         String realm = relyingPartyBean.getRealm();
         String returnTo = openIdServiceUrl + "?dialogueId=" + dialogue.get().getId();
         AuthRequest authReq = openIdConsumerManager.authenticate(discovered, returnTo, realm);

         if (attributes != null && attributes.size() > 0)
         {
            FetchRequest fetch = FetchRequest.createFetchRequest();
            for (OpenIdRequestedAttribute attribute : attributes)
            {
               fetch.addAttribute(attribute.getAlias(), attribute.getTypeUri(), attribute.isRequired());
            }
            // attach the extension to the authentication request
            authReq.addExtension(fetch);
         }

         String url = authReq.getDestinationUrl(true);

         responseHandler.sendHttpRedirectToUserAgent(url, response);
      }
      catch (OpenIDException e)
      {
         log.warn("Authentication failed", e);
         openIdRelyingPartySpi.get().loginFailed(e.getMessage(), responseHandler.createResponseHolder(response));
      }
   }

   private OpenIdPrincipal createPrincipal(String identifier, URL openIdProvider, Map<String, List<String>> attributeValues)
   {
      return new OpenIdPrincipalImpl(identifier, openIdProvider, attributeValues);
   }
}
