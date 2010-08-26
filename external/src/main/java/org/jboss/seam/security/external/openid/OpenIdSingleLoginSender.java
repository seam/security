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

import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.api.OpenIdAttribute;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.ax.FetchRequest;

/**
 * @author Marcel Kolsteren
 * 
 */
@ApplicationScoped
public class OpenIdSingleLoginSender
{
   @Inject
   private OpenIdRequest openIdRequest;

   @Inject
   private ConsumerManager openIdConsumerManager;

   @Inject
   private OpenIdServiceProvider serviceProvider;

   @Inject
   private ResponseHandler responseHandler;

   @Inject
   private Instance<SamlServiceProviderSpi> samlServiceProviderSpi;

   public void sendAuthRequest(String openId)
   {
      try
      {
         @SuppressWarnings("unchecked")
         List<DiscoveryInformation> discoveries = openIdConsumerManager.discover(openId);

         DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);

         openIdRequest.setDiscoveryInformation(discovered);

         String openIdServiceUrl = serviceProvider.getServiceURL(OpenIdService.OPEN_ID_SERVICE);
         String realm = serviceProvider.getRealm();
         AuthRequest authReq = openIdConsumerManager.authenticate(discovered, openIdServiceUrl, realm);

         // Request attributes
         List<OpenIdAttribute> attributes = serviceProvider.getAttributes();
         if (attributes.size() > 0)
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
         samlServiceProviderSpi.get().loginFailed();
      }
   }
}
