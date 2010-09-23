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

import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Object respresenting a person that has been authenticated using OpenID.
 * 
 * @author Marcel Kolsteren
 */
public interface OpenIdPrincipal
{
   /**
    * This identifier holds the OpenID that is owned by the person.
    * 
    * @return the verified OpenID
    */
   String getIdentifier();

   /**
    * The endpoint URL of the authentication service of the OpenID provider that
    * verified that the person owns the OpenID.
    * 
    * @return the OpenID provider authentication endpoint URL
    */
   URL getOpenIdProvider();

   /**
    * The attributes of the person, that have been received from the OpenID
    * provider. It maps aliases of requested attributes to lists of attribute
    * values.
    * 
    * @return the attribute map
    */
   Map<String, List<String>> getAttributeValues();

   /**
    * Convenience method for fetching the first value of the attribute with the
    * given alias. If the attribute doesn't exits, it returns null;
    * 
    * @param alias attribute alias
    * @return the first value of the attribute, or null
    */
   String getAttribute(String alias);
}
