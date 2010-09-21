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
package org.jboss.seam.security.externaltest.integration.openid.rp;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.OpenIdPrincipal;
import org.jboss.seam.security.external.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.spi.OpenIdRelyingPartySpi;

import com.google.common.collect.Lists;

public class OpenIdRpApplicationMock implements OpenIdRelyingPartySpi
{
   @Inject
   private OpenIdRelyingPartyApi rpApi;

   @Dialogued
   public void login(String identifier, boolean fetchEmail, HttpServletResponse response)
   {
      if (fetchEmail)
      {
         OpenIdRequestedAttribute requestedAttribute = new OpenIdRequestedAttribute("email", "http://axschema.org/contact/email", true, 1);
         rpApi.login(identifier, Lists.newArrayList(requestedAttribute), response);
      }
      else
      {
         rpApi.login(identifier, null, response);
      }
   }

   public void loginFailed(String message, ResponseHolder responseHolder)
   {
      writeMessageToResponse("Login failed: " + message, responseHolder);
   }

   public void loginSucceeded(OpenIdPrincipal principal, ResponseHolder responseHolder)
   {
      if (principal.getAttributeValues() != null)
      {
         String email = (String) principal.getAttribute("email");
         writeMessageToResponse("Login succeeded (" + principal.getIdentifier() + ", email " + email + ")", responseHolder);
      }
      else
      {
         writeMessageToResponse("Login succeeded (" + principal.getIdentifier() + ")", responseHolder);
      }
   }

   private void writeMessageToResponse(String message, ResponseHolder responseHolder)
   {
      try
      {
         responseHolder.getResponse().getWriter().print(message);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }
}
