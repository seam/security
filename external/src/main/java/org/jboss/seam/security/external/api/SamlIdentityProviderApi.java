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
import java.util.Set;

import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.saml.idp.SamlExternalServiceProvider;
import org.jboss.seam.security.external.saml.idp.SamlIdpSession;

/**
 * @author Marcel Kolsteren
 * 
 */
public interface SamlIdentityProviderApi extends SamlEntityApi
{
   void authenticationSucceeded(SamlNameId nameId, List<AttributeType> attributes);

   void authenticationSucceeded(SamlIdpSession sessionToJoin);

   void authenticationFailed();

   Set<SamlIdpSession> getSessions();

   List<SamlExternalServiceProvider> getServiceProviders();

   void logout(SamlPrincipal principal, List<String> indexes);

   boolean isWantAuthnRequestsSigned();

   void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned);

   boolean isSingleLogoutMessagesSigned();

   void setSingleLogoutMessagesSigned(boolean singleLogoutMessagesSigned);

   boolean isWantSingleLogoutMessagesSigned();

   void setWantSingleLogoutMessagesSigned(boolean wantSingleLogoutMessagesSigned);
}
