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
import org.jboss.seam.security.external.openid.OpenIdAuthenticator;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.spi.OpenIdRelyingPartySpi;

public class OpenIdRelyingPartySpiImpl implements OpenIdRelyingPartySpi
{
   @Inject
   private ServletContext servletContext;

   @Inject OpenIdAuthenticator openIdAuthenticator;

   public void loginSucceeded(OpenIdPrincipal principal, ResponseHolder responseHolder)
   {
      try
      {
         openIdAuthenticator.success(principal);
         responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/UserInfo.jsf");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void loginFailed(String message, ResponseHolder responseHolder)
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
}
