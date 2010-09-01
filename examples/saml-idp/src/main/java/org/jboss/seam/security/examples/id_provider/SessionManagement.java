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
package org.jboss.seam.security.examples.id_provider;

import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.Model;
import javax.inject.Inject;

import org.jboss.seam.security.external.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.api.SamlIdentityProviderConfigurationApi;
import org.jboss.seam.security.external.saml.idp.SamlExternalServiceProvider;

@Model
public class SessionManagement
{
   @Inject
   private SamlIdentityProviderApi idpApi;

   @Inject
   private SamlIdentityProviderConfigurationApi idpConfApi;

   public List<String> getNonParticipatingServiceProviders()
   {
      List<String> serviceProviders = new LinkedList<String>();
      for (SamlExternalServiceProvider sp : idpConfApi.getServiceProviders())
      {
         if (!isSessionParticipant(sp))
         {
            serviceProviders.add(sp.getEntityId());
         }
      }
      return serviceProviders;
   }

   public List<String> getParticipatingServiceProviders()
   {
      List<String> serviceProviders = new LinkedList<String>();
      for (SamlExternalServiceProvider sp : idpConfApi.getServiceProviders())
      {
         if (isSessionParticipant(sp))
         {
            serviceProviders.add(sp.getEntityId());
         }
      }
      return serviceProviders;
   }

   private boolean isSessionParticipant(SamlExternalServiceProvider sp)
   {
      return idpApi.getSession().getServiceProviders().contains(sp);
   }

   public void samlRemoteLogin(String spEntityId)
   {
      if (idpApi.getSession() == null)
      {
         throw new RuntimeException("No local SAML session.");
      }
      idpApi.remoteLogin(spEntityId, null);
   }
}
