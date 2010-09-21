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

import javax.servlet.http.HttpServletResponse;

/**
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
    * @param attributes attributes that are requested
    */
   void login(String identifier, List<OpenIdRequestedAttribute> attributes, HttpServletResponse response);
}
