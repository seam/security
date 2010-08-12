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

import javax.inject.Inject;
import javax.naming.ConfigurationException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external_authentication.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.protocol.LogoutRequestType;

public class SamlSingleLogoutSender
{
   @Inject
   private Requests requests;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private SamlMessageFactory samlMessageFactory;

   public void sendSingleLogoutRequestToIDP(HttpServletRequest request, HttpServletResponse response, Identity identity)
   {
      SeamSamlPrincipal principal = (SeamSamlPrincipal) null; // FIXME:
                                                              // identity.getPrincipal()
                                                              // is not
                                                              // available any
                                                              // more
      SamlIdentityProvider idp = (SamlIdentityProvider) principal.getIdentityProvider();
      LogoutRequestType logoutRequest;
      try
      {
         logoutRequest = samlMessageFactory.createLogoutRequest(principal);
         requests.addRequest(logoutRequest.getID(), idp, null);
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException(e);
      }

      samlMessageSender.sendRequestToIDP(request, response, idp, SamlProfile.SINGLE_LOGOUT, logoutRequest);
   }
}
