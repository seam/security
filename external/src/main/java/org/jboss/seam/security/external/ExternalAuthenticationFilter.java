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
package org.jboss.seam.security.external;

import java.io.IOException;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external.configuration.Configuration;
import org.jboss.seam.security.external.configuration.SamlIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Seam Servlet Filter supporting SAMLv2 authentication. It implements the Web
 * Browser SSO Profile. For outgoing authentication requests it can use either
 * HTTP Post or HTTP Redirect binding. For the responses, it uses HTTP Post
 * binding, with or without signature validation.
 */
@WebFilter
public class ExternalAuthenticationFilter implements Filter
{
   public static final String IDP_ENTITY_ID_PARAMETER = "idpEntityId";

   public static final String RETURN_URL_PARAMETER = "returnUrl";

   public static final String OPEN_ID_PARAMETER = "openId";

   private final Logger log = LoggerFactory.getLogger(ExternalAuthenticationFilter.class);

   @Inject
   private Configuration configuration;

   @Inject
   private SamlMessageReceiver samlMessageReceiver;

   @Inject
   private OpenIdSingleLoginReceiver openIdSingleLoginReceiver;

   @Inject
   private SamlSingleSignOnSender samlSingleSignOnSender;

   @Inject
   private OpenIdSingleLoginSender openIdSingleLoginSender;

   @Inject
   private SamlSingleLogoutSender samlSingleLogoutSender;

   @Inject
   private SamlMetaDataProvider samlMetaDataProvider;

   @Inject
   private OpenIdXrdsProvider openIdXrdsProvider;

   @Inject
   private Instance<Identity> identity;

   public void init(FilterConfig filterConfig) throws ServletException
   {
      configuration.setContextRoot(filterConfig.getServletContext().getContextPath());
   }

   public void doFilter(ServletRequest request, ServletResponse response, final FilterChain chain) throws IOException, ServletException
   {
      if (!(request instanceof HttpServletRequest))
      {
         throw new ServletException("This filter can only process HttpServletRequest requests");
      }

      final HttpServletRequest httpRequest = (HttpServletRequest) request;
      final HttpServletResponse httpResponse = (HttpServletResponse) response;

      final ExternalAuthenticationService service = determineService(httpRequest);

      if (service != null)
      {
         try
         {
            doFilter(httpRequest, httpResponse, service);
         }
         catch (InvalidRequestException e)
         {
            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            if (log.isInfoEnabled())
            {
               log.info("Bad request received from {0} ({1})", new Object[] { e.getCause(), httpRequest.getRemoteHost(), e.getDescription() });
            }
         }
      }
      else
      {
         // Request is not related to external authentication. Pass the request
         // on to
         // the next filter in the chain.
         chain.doFilter(httpRequest, httpResponse);
      }
   }

   private void doFilter(HttpServletRequest httpRequest, HttpServletResponse httpResponse, ExternalAuthenticationService service) throws InvalidRequestException, IOException, ServletException
   {
      switch (service)
      {
      case OPEN_ID_SERVICE:
         openIdSingleLoginReceiver.handleIncomingMessage(httpRequest, httpResponse);
         break;
      case SAML_SINGLE_LOGOUT_SERVICE:
         samlMessageReceiver.handleIncomingSamlMessage(SamlProfile.SINGLE_LOGOUT, httpRequest, httpResponse);
         break;
      case SAML_ASSERTION_CONSUMER_SERVICE:
         samlMessageReceiver.handleIncomingSamlMessage(SamlProfile.SINGLE_SIGN_ON, httpRequest, httpResponse);
         break;
      case AUTHENTICATION_SERVICE:
         String returnUrl = httpRequest.getParameter(RETURN_URL_PARAMETER);

         String providerName = httpRequest.getParameter(IDP_ENTITY_ID_PARAMETER);
         if (providerName != null)
         {
            SamlIdentityProvider identityProvider = configuration.getServiceProvider().getSamlConfiguration().getSamlIdentityProviderByEntityId(providerName);

            // User requested a page for which login is required. Return a page
            // that instructs the browser to post an authentication request to
            // the IDP.
            if (identityProvider instanceof SamlIdentityProvider)
            {
               samlSingleSignOnSender.sendAuthenticationRequestToIDP(httpRequest, httpResponse, (SamlIdentityProvider) identityProvider, returnUrl);
            }
            else
            {
               throw new RuntimeException("Only SAML identity providers are supported in this version");
            }
         }
         else
         {
            String openId = httpRequest.getParameter(OPEN_ID_PARAMETER);
            openIdSingleLoginSender.sendAuthRequest(openId, returnUrl, httpResponse);
         }
         break;
      case LOGOUT_SERVICE:
         if (!identity.get().isLoggedIn())
         {
            throw new RuntimeException("User not logged in.");
         }
         // FIXME SeamSamlPrincipal principal = (SeamSamlPrincipal)
         // identity.getPrincipal();
         SeamSamlPrincipal principal = (SeamSamlPrincipal) httpRequest.getUserPrincipal();
         SamlIdentityProvider idp = principal.getIdentityProvider();
         if (!(idp instanceof SamlIdentityProvider))
         {
            throw new RuntimeException("Only SAML identity providers are supported in this version");
         }

         samlSingleLogoutSender.sendSingleLogoutRequestToIDP(httpRequest, httpResponse, identity.get());
         break;
      case SAML_META_DATA_SERVICE:

         samlMetaDataProvider.writeMetaData(httpResponse.getOutputStream());
         httpResponse.setCharacterEncoding("UTF-8");
         httpResponse.setContentType("application/xml");
         httpResponse.flushBuffer();
         break;
      case OPEN_ID_XRDS_SERVICE:

         openIdXrdsProvider.writeMetaData(httpResponse.getOutputStream());
         httpResponse.setCharacterEncoding("UTF-8");
         httpResponse.setContentType("application/xrds+xml");
         httpResponse.flushBuffer();
         break;
      default:
         throw new RuntimeException("Unsupported service " + service);
      }
   }

   private ExternalAuthenticationService determineService(HttpServletRequest httpRequest)
   {
      String path = ((HttpServletRequest) httpRequest).getRequestURI().replace(".seam", "");

      for (ExternalAuthenticationService service : ExternalAuthenticationService.values())
      {
         if (path.endsWith("/" + service.getName()))
         {
            return service;
         }
      }
      return null;
   }

   public void destroy()
   {
   }
}
