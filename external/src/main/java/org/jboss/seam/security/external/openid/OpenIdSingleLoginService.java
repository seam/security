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

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.api.OpenIdAttribute;
import org.jboss.seam.security.external.api.OpenIdPrincipal;
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
public class OpenIdSingleLoginService
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

   @SuppressWarnings("unchecked")
   public void handleIncomingMessage(HttpServletRequest httpRequest) throws InvalidRequestException
   {
      try
      {
         // extract the parameters from the authentication response
         // (which comes in as a HTTP request from the OpenID provider)
         ParameterList response = new ParameterList(httpRequest.getParameterMap());

         // retrieve the previously stored discovery information
         DiscoveryInformation discovered = openIdRequest.getDiscoveryInformation();

         // extract the receiving URL from the HTTP request
         StringBuffer receivingURL = httpRequest.getRequestURL();
         String queryString = httpRequest.getQueryString();
         if (queryString != null && queryString.length() > 0)
            receivingURL.append("?").append(httpRequest.getQueryString());

         // verify the response; ConsumerManager needs to be the same
         // (static) instance used to place the authentication request
         VerificationResult verification = openIdConsumerManager.verify(receivingURL.toString(), response, discovered);

         // examine the verification result and extract the verified identifier
         Identifier identifier = verification.getVerifiedId();

         if (identifier != null)
         {
            AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();

            Map<String, List<String>> attributes = null;
            if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX))
            {
               FetchResponse fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);

               attributes = fetchResp.getAttributes();
            }

            OpenIdPrincipal principal = createPrincipal(identifier.getIdentifier(), discovered.getOPEndpoint(), attributes);

            openIdRelyingPartySpi.get().loginSucceeded(principal);
         }
         else
         {
            openIdRelyingPartySpi.get().loginFailed();
         }
      }
      catch (OpenIDException e)
      {
         throw new RuntimeException(e);
      }
   }

   private OpenIdPrincipal createPrincipal(String identifier, URL openIdProvider, Map<String, List<String>> attributes)
   {
      return new OpenIdPrincipal(identifier, openIdProvider, attributes);
   }

   public void sendAuthRequest(String openId, List<OpenIdAttribute> attributes)
   {
      try
      {
         @SuppressWarnings("unchecked")
         List<DiscoveryInformation> discoveries = openIdConsumerManager.discover(openId);

         DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);

         openIdRequest.setDiscoveryInformation(discovered);

         String openIdServiceUrl = relyingPartyBean.getServiceURL(OpenIdService.OPEN_ID_SERVICE);
         String realm = relyingPartyBean.getRealm();
         AuthRequest authReq = openIdConsumerManager.authenticate(discovered, openIdServiceUrl, realm);

         if (attributes != null && attributes.size() > 0)
         {
            FetchRequest fetch = FetchRequest.createFetchRequest();
            for (OpenIdAttribute attribute : attributes)
            {
               fetch.addAttribute(attribute.getAlias(), attribute.getTypeUri(), attribute.isRequired());
            }
            // attach the extension to the authentication request
            authReq.addExtension(fetch);
         }

         String url = authReq.getDestinationUrl(true);

         responseHandler.sendHttpRedirectToUserAgent(url);
      }
      catch (OpenIDException e)
      {
         openIdRelyingPartySpi.get().loginFailed();
      }
   }
}
