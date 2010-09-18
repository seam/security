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

/**
 * @author Marcel Kolsteren
 * 
 */
public class OpenIdRequestedAttribute
{
   private String alias;
   private String typeUri;
   private boolean required;
   private Integer count;

   public OpenIdRequestedAttribute()
   {

   }

   public OpenIdRequestedAttribute(String alias, String typeUri, boolean required, Integer count)
   {
      super();
      this.alias = alias;
      this.typeUri = typeUri;
      this.required = required;
      this.count = count;
   }

   public String getAlias()
   {
      return alias;
   }

   public void setAlias(String alias)
   {
      this.alias = alias;
   }

   public String getTypeUri()
   {
      return typeUri;
   }

   public void setTypeUri(String typeUri)
   {
      this.typeUri = typeUri;
   }

   public boolean isRequired()
   {
      return required;
   }

   public void setRequired(boolean required)
   {
      this.required = required;
   }

   public Integer getCount()
   {
      return count;
   }

   public void setCount(Integer count)
   {
      this.count = count;
   }

}
