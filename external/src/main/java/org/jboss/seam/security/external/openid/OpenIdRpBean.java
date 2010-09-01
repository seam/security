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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.EntityBean;
import org.jboss.seam.security.external.api.OpenIdAttribute;
import org.jboss.seam.security.external.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.api.OpenIdRelyingPartyConfigurationApi;
import org.jboss.seam.security.external.dialogues.api.Dialogued;

/**
 * @author Marcel Kolsteren
 * 
 */
public class OpenIdRpBean extends EntityBean implements OpenIdRelyingPartyApi, OpenIdRelyingPartyConfigurationApi
{
   @Inject
   private OpenIdSingleLoginService openIdSingleLoginSender;

   @Inject
   private ServletContext servletContext;

   @Dialogued
   public void login(String openId, List<OpenIdAttribute> attributes)
   {
      openIdSingleLoginSender.sendAuthRequest(openId, attributes);
   }

   public String getServiceURL(OpenIdService service)
   {
      String path = servletContext.getContextPath() + "/openid/" + service.getName();
      return createURL(path);
   }

   public String getRealm()
   {
      return createURL("");
   }

   private String createURL(String path)
   {
      try
      {
         if (protocol.equals("http") && port == 80 || protocol.equals("https") && port == 443)
         {
            return new URL(protocol, hostName, path).toExternalForm();
         }
         else
         {
            return new URL(protocol, hostName, port, path).toExternalForm();
         }
      }
      catch (MalformedURLException e)
      {
         throw new RuntimeException(e);
      }
   }
}
