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
package org.jboss.seam.security.examples.id_consumer;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.saml.sp.SamlSpSession;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.slf4j.Logger;

public class SamlServiceProviderSpiImpl implements SamlServiceProviderSpi
{
   @Inject
   SamlServiceProviderApi samlServiceProviderApi;

   @Inject
   ResponseHolder responseHolder;

   @Inject
   private Logger log;

   @Inject
   private ServletContext servletContext;

   public void loginSucceeded(SamlSpSession session)
   {
      try
      {
         responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/UserInfo.jsf");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void loginFailed()
   {
      try
      {
         responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/AuthenticationFailed.jsf");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void globalLogoutFailed(String statusCode)
   {
      try
      {
         responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/GlobalLogoutFailed.jsf");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void globalLogoutSucceeded()
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

   public void loggedIn(SamlSpSession session, String url)
   {
      try
      {
         if (url != null)
         {
            responseHolder.getResponse().sendRedirect(url);
         }
         else
         {
            responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/UserInfo.jsf");
         }
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void loggedOut(SamlSpSession session)
   {
      log.info("User " + session.getPrincipal().getNameId() + " has been logged out.");
   }
}
