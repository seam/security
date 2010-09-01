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

import java.util.List;

import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.saml.idp.SamlIdpSession;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

/**
 * @author Marcel Kolsteren
 * 
 */

public interface SamlIdentityProviderApi
{
   /**
    * Creates a local SAML session for the user with the given name and
    * attributes. This call is typically done before a remoteLogin or an
    * authenticationSucceeded call.
    * 
    * @param nameId
    * @param attributes
    */
   void localLogin(SamlNameId nameId, List<AttributeType> attributes);

   /**
    * <p>
    * Logs the user in remotely in the application of the given service
    * provider. If the remote URL is specified, the service provider will
    * redirect the user to that URL. Otherwise, the service provider will
    * determine for itself which page is shown to the user.
    * </p>
    * 
    * <p>
    * In SAML terms, this call results in an "unsolicited login" at the side of
    * the service provider.
    * </p>
    * 
    * @param spEntityId the entity id of the remote service provider
    * @param remoteUrl the URL where the user agent needs to be redirected to by
    *           the service provider (can be null)
    */
   void remoteLogin(String spEntityId, String remoteUrl);

   /**
    * This is one of the possible responses that relate to the SPI call
    * {@link SamlIdentityProviderSpi#authenticate}. If should be called in the
    * same dialogue context as the corresponding SPI call. It instructs the SAML
    * identity provider to send a positive authentication result back to the
    * service provider, using the local SAML session, which must have been
    * established before this call is done.
    */
   void authenticationSucceeded();

   /**
    * This is one of the possible responses that relate to the SPI call
    * {@link SamlIdentityProviderSpi#authenticate}. If should be called in the
    * same dialogue context as the corresponding SPI call. It instructs the SAML
    * identity provider to send a positive authentication result back to the
    * service provider.
    */
   void authenticationFailed();

   /**
    * Gets the current SAML session. This contains information about the logged
    * in user, and the external service providers that take part in this
    * session.
    * 
    * @return the session
    */
   SamlIdpSession getSession();

   /**
    * Removes the local SAML session for the current user. This use case is
    * considered out of scope by the SAML spec (see the SAMLv2 Profiles
    * document, section 4.4). External service providers that take part in the
    * session are not informed about the fact that the shared session has been
    * removed at the identity provider side.
    */
   void localLogout();

   /**
    * Globally logs out the current user. This leads to a "single logout" where
    * the identity provider logs out the user from all service providers that
    * participate in the current session. The result of the global logout is
    * reported asynchronously through the SPI.
    */
   void globalLogout();
}
