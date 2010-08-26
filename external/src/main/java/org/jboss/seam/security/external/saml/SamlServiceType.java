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
package org.jboss.seam.security.external.saml;

/**
 * @author Marcel Kolsteren
 * 
 */
public enum SamlServiceType
{
   SAML_SINGLE_SIGN_ON_SERVICE("SingleSignOnService", SamlProfile.SINGLE_SIGN_ON),

   SAML_ASSERTION_CONSUMER_SERVICE("AssertionConsumerService", SamlProfile.SINGLE_SIGN_ON),

   SAML_SINGLE_LOGOUT_SERVICE("SingleLogoutService", SamlProfile.SINGLE_LOGOUT),

   SAML_META_DATA_SERVICE("MetaDataService", null);

   private String name;

   private SamlProfile profile;

   private SamlServiceType(String name, SamlProfile profile)
   {
      this.name = name;
      this.profile = profile;
   }

   public String getName()
   {
      return name;
   }

   public SamlProfile getProfile()
   {
      return profile;
   }

   public static SamlServiceType getByName(String name)
   {
      for (SamlServiceType service : values())
      {
         if (service.getName().equals(name))
         {
            return service;
         }
      }
      return null;
   }
}
