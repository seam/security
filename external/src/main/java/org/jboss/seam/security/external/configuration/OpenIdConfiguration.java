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
package org.jboss.seam.security.external.configuration;

import java.util.List;

import org.jboss.seam.security.external.jaxb.config.OpenIdAttributeType;
import org.jboss.seam.security.external.jaxb.config.OpenIdConfigType;

public class OpenIdConfiguration
{
   private List<OpenIdAttributeType> attributes;

   private String defaultOpenIdProvider;

   public OpenIdConfiguration(OpenIdConfigType openIdConfig)
   {
      attributes = openIdConfig.getAttribute();
      defaultOpenIdProvider = openIdConfig.getDefaultOpenIdProvider();
   }

   public List<OpenIdAttributeType> getAttributes()
   {
      return attributes;
   }

   public String getDefaultOpenIdProvider()
   {
      return defaultOpenIdProvider;
   }
}
