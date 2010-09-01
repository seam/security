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

import org.jboss.seam.security.external.saml.sp.SamlExternalIdentityProvider;

/**
 * @author Marcel Kolsteren
 * 
 */
public interface SamlServiceProviderConfigurationApi extends SamlEntityConfigurationApi
{
   /**
    * Returns a list with all identity providers that are supported (trusted).
    * This allows the API client to present the list to the user, so that the
    * user can choose the provider that needs to be used for doing the login.
    * 
    * @return list of identity providers
    */
   List<SamlExternalIdentityProvider> getIdentityProviders();

   /**
    * If this property is enabled, all authentication requests targeted at
    * identity providers will be signed. The property is disabled by default.
    * When enabling it, be sure to add a signing key by calling
    * {@link SamlEntityConfigurationApi#setSigningKey(String, String, String, String)}
    * .
    * 
    * @return true iff the authentication requests are signed
    */
   boolean isAuthnRequestsSigned();

   /**
    * See {@link #isAuthnRequestsSigned}.
    */
   void setAuthnRequestsSigned(boolean authnRequestsSigned);

   /**
    * This property, which is enabled by default, determines whether incoming
    * authentication responses from the identity provider are required to have a
    * valid signature. It is strongly discouraged to disabled signature
    * validation, because this opens possibilities for sending fake
    * authentication responses to the service provider.
    * 
    * @return true iff incoming assertions need to have a valid signature
    */
   boolean isWantAssertionsSigned();

   /**
    * See {@link #isWantAssertionsSigned()}.
    */
   void setWantAssertionsSigned(boolean wantAssertionsSigned);

   /**
    * This property indicates whether outgoing single logout messages are
    * signed. True by default, and the advice is not to disable this property,
    * unless you understand the security risks of doing so.
    * 
    * @return true iff the single logout requests (sent to identity providers)
    *         are signed
    */
   boolean isSingleLogoutMessagesSigned();

   /**
    * See {@link #isSingleLogoutMessagesSigned()}.
    */
   void setSingleLogoutMessagesSigned(boolean singleLogoutMessagesSigned);

   /**
    * This property indicates whether incoming single logout requests are
    * required to have a valid signature. True by default, and the advice is not
    * to disable this property, unless you understand the security risks of
    * doing so.
    * 
    * @return true iff incoming single logout requests need to have a valid
    *         signature
    */
   boolean isWantSingleLogoutMessagesSigned();

   /**
    * See {@link #isWantSingleLogoutMessagesSigned()}.
    */
   void setWantSingleLogoutMessagesSigned(boolean wantSingleLogoutMessagesSigned);
}
