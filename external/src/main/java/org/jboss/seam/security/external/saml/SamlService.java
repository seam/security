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

import java.util.LinkedList;
import java.util.List;

import org.jboss.seam.security.external.jaxb.samlv2.metadata.EndpointType;
import org.jboss.seam.security.external.saml.api.SamlBinding;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlService
{
   private SamlProfile profile;

   private List<SamlEndpoint> serviceEndpoints = new LinkedList<SamlEndpoint>();

   public SamlService(SamlProfile profile, List<? extends EndpointType> endpoints)
   {
      this.profile = profile;

      for (EndpointType endpoint : endpoints)
      {
         SamlBinding samlBinding = null;
         if (endpoint.getBinding().endsWith("HTTP-Redirect"))
         {
            samlBinding = SamlBinding.HTTP_Redirect;
         }
         else if (endpoint.getBinding().endsWith("HTTP-POST"))
         {
            samlBinding = SamlBinding.HTTP_Post;
         }
         else
         {
            // ignore other bindings
         }
         if (samlBinding != null)
         {
            SamlEndpoint samlEndpoint = new SamlEndpoint(this, samlBinding, endpoint.getLocation(), endpoint.getResponseLocation());
            serviceEndpoints.add(samlEndpoint);
         }
      }
   }

   public SamlProfile getProfile()
   {
      return profile;
   }

   public List<SamlEndpoint> getServiceEndpoints()
   {
      return serviceEndpoints;
   }

   public SamlEndpoint getEndpointForBinding(SamlBinding samlBinding)
   {
      for (SamlEndpoint endpoint : serviceEndpoints)
      {
         if (endpoint.getBinding() == samlBinding)
         {
            return endpoint;
         }
      }

      return null;
   }
}
