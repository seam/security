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

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external_authentication.configuration.Binding;
import org.jboss.seam.security.external_authentication.configuration.SamlEndpoint;
import org.jboss.seam.security.external_authentication.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external_authentication.configuration.ServiceProvider;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.StatusResponseType;

public class SamlSingleLogoutReceiver
{
   @Inject
   private SamlMessageFactory samlMessageFactory;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private Identity identity;

   @Inject
   private ServiceProvider serviceProvider;

   public void processIDPRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, RequestAbstractType request, SamlIdentityProvider idp) throws InvalidRequestException
   {
      if (!(request instanceof LogoutRequestType))
      {
         throw new InvalidRequestException("Request should be a single logout request.");
      }

      if (!identity.isLoggedIn())
      {
         throw new InvalidRequestException("No active session to logout.");
      }

      // FIXME: Identity.instance().logout();

      StatusResponseType response = samlMessageFactory.createStatusResponse(request, SamlConstants.STATUS_SUCCESS, null);

      Binding binding = httpRequest.getMethod().equals("POST") ? Binding.HTTP_Post : Binding.HTTP_Redirect;
      SamlEndpoint endpoint = idp.getService(SamlProfile.SINGLE_LOGOUT).getEndpointForBinding(binding);

      samlMessageSender.sendResponseToIDP(httpRequest, httpResponse, idp, endpoint, response);
   }

   public void processIDPResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse, StatusResponseType response, RequestContext requestContext, SamlIdentityProvider idp)
   {
      if (response.getStatus() != null && response.getStatus().getStatusCode().getValue().equals(SamlConstants.STATUS_SUCCESS))
      {
         // FIXME Identity.instance().logout();
      }
      else
      {
         throw new RuntimeException("Single logout failed. Status code: " + (response.getStatus() == null ? "null" : response.getStatus().getStatusCode().getValue()));
      }
      try
      {
         httpResponse.sendRedirect(serviceProvider.getLoggedOutUrl());
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }
}
