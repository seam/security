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

/**
 * Attribute requested by the relying party during the authentication of a user.
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface OpenIdRequestedAttribute
{
   /**
    * Name that identifies this requested attribute.
    * 
    * @return the alias
    */
   String getAlias();

   /**
    * Attribute type identifier.
    * 
    * @return the type URI
    */
   String getTypeUri();

   /**
    * Indicates whether the attribute is required.
    * 
    * @return true if required, false otherwise
    */
   boolean isRequired();

   /**
    * Indicates the maximum number of values to be returned by the provider;
    * must be at least 1.
    * 
    * @return maximum number of values
    */
   Integer getCount();
}
