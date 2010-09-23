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
package org.jboss.seam.security.external.openid.api;

import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.spi.OpenIdRelyingPartySpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * API to the OpenID Relying Party (RP) of Seam security. In order to use this
 * API, one of the following alternative beans needs to be activated:
 * 
 * <ul>
 * <li>{@link OpenIdRelyingPartyInApplicationScopeProducer}</li>
 * <li>{@link OpenIdRelyingPartyInVirtualApplicationScopeProducer}</li>
 * </ul>
 * 
 * The former will install the OpenID relying party in application scope, the
 * latter will install it in virtual application scope. The virtual application
 * scope allows for using different provider configurations depending on the
 * server name. See {@link VirtualApplicationScoped}.
 * 
 * <p>
 * This API (implemented by the framework) comes along with an SPI:
 * {@link OpenIdRelyingPartySpi} (implemented by the client application).
 * Dialogues are used to bridge corresponding API and SPI calls (see
 * {@link Dialogued}).
 * </p>
 * 
 * <p>
 * Most methods in this API require that the HTTP response is passed as a
 * parameter. The implementation needs the response, in order to redirect the
 * browser to the relying party. Beware not to touch the HTTP response after one
 * of these method returns.
 * </p>
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface OpenIdRelyingPartyApi
{
   /**
    * Start an OpenID login dialogue.
    * 
    * @param identifier either a Claimed Identifier (identifying the user) or an
    *           OP Identifier (identifying the OpenID Provider where the user
    *           has an account)
    * @param attributes attributes that are requested (they should have
    *           different aliases)
    * @param response the HTTP servlet response
    */
   void login(String identifier, List<OpenIdRequestedAttribute> attributes, HttpServletResponse response);

   /**
    * Creates a request to fetch a certain attribute from the OpenID Provider.
    * The resulting object can be passed to the {@link #login} method.
    * 
    * @param alias name that identifies this requested attribute
    * @param typeUri attribute type identifier
    * @param required indicates whether the attribute is required
    * @param count indicates the maximum number of values to be returned by the
    *           provider; must be at least 1
    * 
    * @return the requested attribute
    */
   OpenIdRequestedAttribute createOpenIdRequestedAttribute(String alias, String typeUri, boolean required, Integer count);
}
