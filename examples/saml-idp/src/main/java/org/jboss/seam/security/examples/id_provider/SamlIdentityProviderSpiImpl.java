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
package org.jboss.seam.security.examples.id_provider;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.logging.Logger;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

public class SamlIdentityProviderSpiImpl implements SamlIdentityProviderSpi
{
   @Inject
   private Logger log;

   @Inject
   private ServletContext servletContext;

   @Inject
   private Identity identity;

   @Inject
   private SamlIdentityProviderApi idpApi;

   public void authenticate(ResponseHolder responseHolder)
   {
      if (identity.isLoggedIn())
      {
         idpApi.authenticationSucceeded(responseHolder.getResponse());
      }
      else
      {
         responseHolder.redirectWithDialoguePropagation(servletContext.getContextPath() + "/Login.jsf");
      }
   }

   public void globalLogoutFailed(ResponseHolder responseHolder)
   {
      try
      {
         responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/SingleLogoutFailed.jsf");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void globalLogoutSucceeded(ResponseHolder responseHolder)
   {
      try
      {
         responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/Login.jsf");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void loggedOut(SamlIdpSession session)
   {
      log.info("Unsolicited logout for user " + session.getPrincipal().getNameId().getValue() + ".");
   }
}
