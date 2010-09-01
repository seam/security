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
package org.jboss.seam.security.external.api;

import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.sp.SamlSpInApplicationScopeProducer;
import org.jboss.seam.security.external.saml.sp.SamlSpInVirtualApplicationScopeProducer;
import org.jboss.seam.security.external.saml.sp.SamlSpSession;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.jboss.seam.security.external.spi.SamlSingleUserServiceProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * API to the SAMLv2 compliant service provider. In order to use this API, one
 * of the following alternative beans need to be activated:
 * 
 * <ul>
 * <li>{@link SamlSpInApplicationScopeProducer}</li>
 * <li>{@link SamlSpInVirtualApplicationScopeProducer}</li>
 * </ul>
 * 
 * The former will install the service provider in application scope, the latter
 * will install it in virtual application scope. The virtual application scope
 * allows for using different service provider configurations depending on the
 * server name. See {@link VirtualApplicationScoped}
 * 
 * <p>
 * This API (implemented by the framework) comes along with an SPI:
 * {@link SamlServiceProviderSpi} (implemented by the client application).
 * Dialogues are used to bridge corresponding API and SPI calls (see
 * {@link Dialogued}).
 * </p>
 * 
 * <p>
 * All methods in this API, except the {@link #logout} method, require that the
 * request scoped {@link ResponseHolder} bean contains a link to the current
 * HTTP response. The implementation needs to response, in order to redirect the
 * browser to the identity provider. Beware not to touch the HTTP response after
 * one of these method returns.
 * </p>
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface SamlServiceProviderApi
{
   /**
    * Sends the user agent to the site of the given identity provider, where the
    * user can be authenticated. When the call returns, a redirect on the HTTP
    * response has taken place. The response of the identity provider will be
    * sent asynchronously through the SPI methods
    * {@link SamlSingleUserServiceProviderSpi#loginSucceeded(OpenIdSession)} or
    * {@link SamlSingleUserServiceProviderSpi#loginFailed(OpenIdSession)}. If
    * the method is called within a dialogue, that same dialogue will be active
    * when the SPI method is called. Thus, the dialogue can be used to store API
    * client state that needs to survive the sign on process.
    * 
    * @param idpEntityId
    */
   public void login(String idpEntityId);

   /**
    * <p>
    * Locally logs out the user. This use case is considered out of scope by the
    * SAML spec (see the SAMLv2 Profiles document, section 4.4). The local
    * logout means that the session established by the SAML SP is not used any
    * more by the application. So when the SAML SP will receive a logout request
    * for this session in the future, it won't pass that on to the application.
    * </p>
    * 
    * <p>
    * This method doesn't write the HTTP response.
    * </p>
    */
   public void localLogout();

   /**
    * Globally logs out the user. The browser of the user is redirected to the
    * site of the identity provider, so that the identity provider can logout
    * the user from all applications that share the same session at the identity
    * provider. The result of the logout operation is reported back
    * asynchronously through the SPI methods
    * {@link SamlSingleUserServiceProviderSpi#globalLogoutSucceeded()} and
    * {@link SamlSingleUserServiceProviderSpi#singleLogoutFailed()}. If this
    * method is called with an active dialogue scope, the same dialogue will be
    * active when the SPI method is called. This allows the API client to store
    * state information in the dialogue.
    */
   public void globalLogout();

   /**
    * Gets the current session (login). If there is no active session, null is
    * returned.
    * 
    * @return active session, or null
    */
   public SamlSpSession getSession();
}
