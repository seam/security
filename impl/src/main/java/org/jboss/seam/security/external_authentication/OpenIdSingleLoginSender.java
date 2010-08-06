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
import java.util.List;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.events.LoginFailedEvent;
import org.jboss.seam.security.events.PreAuthenticateEvent;
import org.jboss.seam.security.external_authentication.configuration.ServiceProvider;
import org.jboss.seam.security.external_authentication.jaxb.config.OpenIdAttributeType;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.ax.FetchRequest;

@Named("org.jboss.seam.security.external_authentication.openIdSingleLoginSender")
public class OpenIdSingleLoginSender
{
   @Inject
   private OpenIdRequest openIdRequest;

   @Inject
   private ConsumerManager openIdConsumerManager;

   @Inject
   private ServiceProvider serviceProvider;

   @Inject
   private BeanManager manager;

   public String sendAuthRequest(String openId, String returnUrl, HttpServletResponse httpResponse)
   {
      try
      {
         @SuppressWarnings("unchecked")
         List<DiscoveryInformation> discoveries = openIdConsumerManager.discover(openId);

         DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);

         openIdRequest.setDiscoveryInformation(discovered);
         openIdRequest.setReturnUrl(returnUrl);

         String openIdServiceUrl = serviceProvider.getServiceURL(ExternalAuthenticationService.OPEN_ID_SERVICE);
         String realm = serviceProvider.getOpenIdRealm();
         AuthRequest authReq = openIdConsumerManager.authenticate(discovered, openIdServiceUrl, realm);

         // Request attributes
         List<OpenIdAttributeType> attributes = serviceProvider.getOpenIdConfiguration().getAttributes();
         if (attributes.size() > 0)
         {
            FetchRequest fetch = FetchRequest.createFetchRequest();
            for (OpenIdAttributeType attribute : attributes)
            {
               fetch.addAttribute(attribute.getAlias(), attribute.getTypeUri(), attribute.isRequired());
            }
            // attach the extension to the authentication request
            authReq.addExtension(fetch);
         }

         String url = authReq.getDestinationUrl(true);

         manager.fireEvent(new PreAuthenticateEvent());

         httpResponse.sendRedirect(url);
      }
      catch (OpenIDException e)
      {
         try
         {
            manager.fireEvent(new LoginFailedEvent(new LoginException()));

            httpResponse.sendRedirect(serviceProvider.getFailedAuthenticationUrl());
         }
         catch (IOException e1)
         {
            throw new RuntimeException(e);
         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }

      return null;
   }
}
