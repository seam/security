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

import org.jboss.seam.security.external.api.EntityConfigurationApi;

/**
 * API for accessing the OpenID Relying Party configuration
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface OpenIdRelyingPartyConfigurationApi extends EntityConfigurationApi
{
   /**
    * Gets the URL where the XRDS is served that can be used by OpenID providers
    * for relying party discovery. The XRDS document served at this URL is
    * described in the OpenID 2.0 Authentication specification, section 13.
    * Remark that some OpenID providers (e.g. Yahoo) require that a Yadis
    * discovery on the realm also results in this document. Meeting this
    * requirement is beyond the responsibility and beyond the reach of the Seam
    * OpenID module, because the realm URL is not "handled" by the web
    * application in which the OpenID module lives. Consult the Seam Security
    * documentation for further details about setting up the realm-based
    * discovery.
    * 
    * @return the URL
    */
   String getXrdsURL();

   /**
    * Gets the realm that is used by the relying party. A "realm" is a pattern
    * that represents the part of URL-space for which an OpenID Authentication
    * request is valid. See OpenID 2.0 Authentication specification, section
    * 9.2. The OpenID provider uses the realm as the name of the the relying
    * party site that is presented to the end user.
    * 
    * @return the realm
    */
   String getRealm();
}
