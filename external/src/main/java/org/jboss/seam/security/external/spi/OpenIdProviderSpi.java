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

import java.util.List;

import org.jboss.seam.security.external.api.OpenIdProviderApi;
import org.jboss.seam.security.external.api.OpenIdRequestedAttribute;

/**
 * @author Marcel Kolsteren
 * 
 */
public interface OpenIdProviderSpi
{
   /**
    * This method is called after receipt of an authentication request from a
    * relying party. Upon receipt of this call, the application should try to
    * authenticate the user (either silently or interacting with the user). The
    * result of the authentication needs to be reported back using the API calls
    * {@link OpenIdProviderApi#authenticationSucceeded} or
    * {@link OpenIdProviderApi#authenticationFailed}.
    * 
    * @param realm represents the part of URL-space for which the authentication
    *           is valid; realms are designed to give the end user an indication
    *           of the scope of the authentication request; the application
    *           should present the realm when requesting the end user's approval
    *           for the authentication request
    * @param userName this optional attribute indicates the end user that needs
    *           to be authenticated; if this parameter is null, the application
    *           needs to ask the use for her username
    * @param immediate if this is true, there must be no interaction with the
    *           user (silent authentication)
    */
   void authenticate(String realm, String userName, boolean immediate);

   /**
    * This method is called to check whether a username exists.
    * 
    * @param userName the username
    * @return true if a user with that username exists, false otherwise
    */
   boolean userExists(String userName);

   void fetchParameters(List<OpenIdRequestedAttribute> requestedAttributes);
}
