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
package org.jboss.seam.security.examples.openid;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.List;

import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.openid.api.OpenIdProviderApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.spi.OpenIdProviderSpi;

public class OpenIdProviderSpiImpl implements OpenIdProviderSpi
{
   @Inject
   private ServletContext servletContext;

   @Inject
   private Identity identity;

   @Inject
   private OpenIdProviderApi opApi;

   @Inject
   private Attributes attributes;

   public void authenticate(String realm, String userName, boolean immediate, ResponseHolder responseHolder)
   {
      if (identity.isLoggedIn() && userName != null && !userName.equals(identity.getUserName()))
      {
         opApi.authenticationFailed(responseHolder.getResponse());
      }
      else
      {
         try
         {
            StringBuilder url = new StringBuilder();
            url.append(servletContext.getContextPath());
            url.append("/Login.jsf");
            url.append("?realm=").append(URLEncoder.encode(realm, "UTF-8"));
            if (userName != null)
            {
               url.append("&userName=").append(URLEncoder.encode(userName, "UTF-8"));
            }
            responseHolder.redirectWithDialoguePropagation(url.toString());
         }
         catch (IOException e)
         {
            throw new RuntimeException(e);
         }
      }
   }

   public void fetchParameters(List<OpenIdRequestedAttribute> requestedAttributes, ResponseHolder responseHolder)
   {
      attributes.setRequestedAttributes(requestedAttributes);
      responseHolder.redirectWithDialoguePropagation(servletContext.getContextPath() + "/Attributes.jsf");
   }

   public boolean userExists(String userName)
   {
      return true;
   }
}
