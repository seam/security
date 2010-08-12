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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.annotation.WebFilter;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external_authentication.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external_authentication.configuration.ServiceProvider;

/**
 * Filter that manages the external authentication of users (using, for example,
 * SAML or OpenID).
 */
@Named("externalAuthenticator")
@WebFilter
// FIXME: page scope
public class ExternalAuthenticator
{
   private String returnUrl;

   private String openId;

   @Inject
   private ServiceProvider serviceProvider;

   @Inject
   private Identity identity;

   public void samlSignOn(String idpEntityId)
   {
      if (serviceProvider.getSamlConfiguration() == null)
      {
         throw new RuntimeException("SAML is not configured.");
      }

      SamlIdentityProvider idp = serviceProvider.getSamlConfiguration().getSamlIdentityProviderByEntityId(idpEntityId);
      if (idp == null)
      {
         throw new RuntimeException("Identity provider " + idpEntityId + " not found");
      }

      String authenticationServiceURL = serviceProvider.getServiceURL(ExternalAuthenticationService.AUTHENTICATION_SERVICE);
      Map<String, String> params = new HashMap<String, String>();
      params.put(ExternalAuthenticationFilter.IDP_ENTITY_ID_PARAMETER, idpEntityId);
      params.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
      redirect(authenticationServiceURL, params);
   }

   public void openIdSignOn()
   {
      openIdSignOn(openId);
   }

   public void openIdSignOn(String openId)
   {
      if (serviceProvider.getOpenIdConfiguration() == null)
      {
         throw new RuntimeException("OpenID is not configured.");
      }
      String authenticationServiceURL = serviceProvider.getServiceURL(ExternalAuthenticationService.AUTHENTICATION_SERVICE);
      Map<String, String> params = new HashMap<String, String>();
      params.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
      params.put(ExternalAuthenticationFilter.OPEN_ID_PARAMETER, openId);
      redirect(authenticationServiceURL, params);
   }

   public void singleLogout()
   {
      if (!identity.isLoggedIn())
      {
         throw new RuntimeException("Not logged in");
      }
      if (false /* FIXME !(identity.getPrincipal() instanceof SeamSamlPrincipal) */)
      {
         throw new RuntimeException("Single logout is only supported for SAML");
      }
      String logoutServiceURL = serviceProvider.getServiceURL(ExternalAuthenticationService.LOGOUT_SERVICE);
      redirect(logoutServiceURL, null);
   }

   private void redirect(String urlBase, Map<String, String> params)
   {
      StringBuilder url = new StringBuilder();
      url.append(urlBase);
      if (params != null && params.size() > 0)
      {
         url.append("?");
         boolean first = true;
         for (Map.Entry<String, String> paramEntry : params.entrySet())
         {
            if (first)
            {
               first = false;
            }
            else
            {
               url.append("&");
            }
            url.append(paramEntry.getKey());
            url.append("=");
            try
            {
               String paramValue = paramEntry.getValue();
               if (paramValue == null || paramValue == "")
                  throw new RuntimeException("Param Key:" + paramEntry.getKey() + " has value that is null");
               url.append(URLEncoder.encode(paramValue, "UTF-8"));
            }
            catch (UnsupportedEncodingException e)
            {
               throw new RuntimeException(e);
            }
         }
      }

      try
      {
         FacesContext.getCurrentInstance().getExternalContext().redirect(url.toString());
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);

      }
   }

   public String getReturnUrl()
   {
      return returnUrl;
   }

   public void setReturnUrl(String returnUrl)
   {
      this.returnUrl = returnUrl;
   }

   public String getOpenId()
   {
      return openId;
   }

   public void setOpenId(String openId)
   {
      this.openId = openId;
   }
}
