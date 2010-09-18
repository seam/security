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

import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * @author Marcel Kolsteren
 * 
 */
// TODO: create hash code and equals method
public class OpenIdPrincipal
{
   private String identifier;

   private URL openIdProvider;

   private Map<String, List<String>> attributeValues;

   public OpenIdPrincipal(String identifier, URL openIdProvider, Map<String, List<String>> attributeValues)
   {
      super();
      this.identifier = identifier;
      this.openIdProvider = openIdProvider;
      this.attributeValues = attributeValues;
   }

   public String getIdentifier()
   {
      return identifier;
   }

   public URL getOpenIdProvider()
   {
      return openIdProvider;
   }

   public Map<String, List<String>> getAttributeValues()
   {
      return attributeValues;
   }

   public String getAttribute(String alias)
   {
      List<String> values = attributeValues.get(alias);
      if (values.size() == 0)
      {
         return null;
      }
      else if (values.size() == 1)
      {
         return (String) attributeValues.get(alias).get(0);
      }
      else
      {
         throw new RuntimeException("Attribute has multiple values");
      }
   }

}
