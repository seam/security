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
package org.jboss.seam.security.external.spi;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.saml.sp.SamlSpSession;

/**
 * Interface that needs to be implemented by applications that want to act as a
 * SAML service provider. It is the counterpart of the
 * {@link SamlSingleUserServiceProviderApi}.
 * 
 * All methods in this interface are called within an active request scope,
 * which contains a {@link ResponseHolder} bean that contains the HTTP response.
 * The implementations of the methods are responsible to fill this response.
 * Typically, this will entail a redirect to an application page. There is one
 * exception: the implementation of the loggedOut method must not write to the
 * HTTP response.
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface SamlServiceProviderSpi
{
   /**
    * This method is called after succesfull external authentication of the
    * user. The session contains the details about the user. The call takes
    * place in the same dialogue context as the corresponding API call:
    * {@link SamlSingleUserServiceProviderApi#signOn(String)}. The dialogue can
    * be used, for example, to store the page that the user requested, so that
    * the user can be redirected to this page after login took place.
    * 
    * @param session session
    */
   void loginSucceeded(SamlSpSession session);

   /**
    * This method is called after failed external authentication of the user.
    * The call takes place in the same dialogue context as the corresponding API
    * call.
    */
   void loginFailed();

   /**
    * When the service provider receives an unsolicited login from an identity
    * provider, this method is called.
    * 
    * @param session that has been created for this login
    * @param url URL where the user needs to be redirected to; this URL is
    *           supplied by the identity provider and can be null
    */
   void loggedIn(SamlSpSession session, String url);

   /**
    * This method is the asynchronous callbacks related to
    * {@link SamlSingleUserServiceProviderApi#singleLogout()}. It is called when
    * the single logout was successful. Before this callback is called, the
    * dialogue that was active at the time of the API call is restored. An
    * implementation of this method will typically redirect the user to a page
    * where a message is shown that the user has been logged out.
    */
   void globalLogoutSucceeded();

   /**
    * <p>
    * This method is one of the asynchronous callbacks related to
    * {@link SamlSingleUserServiceProviderApi#singleLogout()}. It is called when
    * the single logout was successful. Before this callback is called, the
    * dialogue that was active at the time of the API call is restored. An
    * implementation of this method will typically redirect the user to a page
    * where a message is shown that the user could not be logged out.
    * </p>
    * 
    * <p>
    * The fact that the single logout failed doesn't mean that all parts of the
    * single logout failed. Possibly only one of the session participants
    * couldn't perform a successful logout, while the others could.
    * </p>
    */
   void globalLogoutFailed(String statusCode);

   /**
    * When the service provider receives a logout request from an identity
    * provider, this method is called. The implementation of this method must
    * take for granted that the user has been logged off. The HTTP response must
    * not be written during this call, because the service provider will use the
    * HTTP response to send a response to the identity provider.
    * 
    * @param session that has been removed
    */
   void loggedOut(SamlSpSession session);
}
