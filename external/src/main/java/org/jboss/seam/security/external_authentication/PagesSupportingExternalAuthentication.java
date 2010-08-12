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

/**
 * Override of Seam's Pages component. It replaces the login page redirection method with a version
 * that redirects to an URL that is filtered by the SamlAuthenticationFilter.
 */

// FIXME

//@ApplicationScoped
//@BypassInterceptors
//@Name("org.jboss.seam.navigation.pages")
//@Injectstall(precedence = Install.FRAMEWORK, classDependencies = "javax.faces.context.FacesContext")
//@Startup
//public class PagesSupportingExternalAuthentication extends Pages
//{
//   @Override
//   public void redirectToLoginView()
//   {
//      notLoggedIn();
//
//      HttpServletRequest httpRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext()
//            .getRequest();
//
//      StringBuffer returnUrl = httpRequest.getRequestURL();
//
//      ExternalAuthenticator externalAuthenticator = (ExternalAuthenticator) Component
//            .getInstance(ExternalAuthenticator.class);
//      externalAuthenticator.setReturnUrl(returnUrl.toString());
//
//      ServiceProvider serviceProvider = Configuration.instance().getServiceProvider();
//
//      // Use default SAML identity provider, if configured
//      SamlConfiguration samlConfiguration = serviceProvider.getSamlConfiguration();
//      if (samlConfiguration != null && samlConfiguration.getDefaultIdentityProvider() != null)
//      {
//         externalAuthenticator.samlSignOn(samlConfiguration.getDefaultIdentityProvider().getEntityId());
//      }
//      else
//      {
//         // Otherwise, use default OpenId identity provider, if configured
//         OpenIdConfiguration openIdConfiguration = serviceProvider.getOpenIdConfiguration();
//         if (openIdConfiguration != null && openIdConfiguration.getDefaultOpenIdProvider() != null)
//         {
//            externalAuthenticator.openIdSignOn(openIdConfiguration.getDefaultOpenIdProvider());
//         }
//         else
//         {
//            // Otherwise, redirect to the login view, so that the user can choose an IDP
//            if (getLoginViewId() == null)
//            {
//               throw new RuntimeException("Login view id not specified in pages.xml.");
//            }
//            Map<String, Object> parameters = new HashMap<String, Object>();
//            parameters.put(ExternalAuthenticationFilter.RETURN_URL_PARAMETER, returnUrl);
//            FacesManager.instance().redirect(getLoginViewId(), parameters, false);
//         }
//      }
//   }
// }
