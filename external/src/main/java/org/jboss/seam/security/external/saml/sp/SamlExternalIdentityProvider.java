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
package org.jboss.seam.security.external.saml.sp;

import java.util.HashMap;
import java.util.Map;

import org.jboss.seam.security.external.jaxb.samlv2.metadata.IDPSSODescriptorType;
import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.saml.SamlService;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlExternalIdentityProvider extends SamlExternalEntity
{
   private Map<SamlProfile, SamlService> services = new HashMap<SamlProfile, SamlService>();

   private boolean wantAuthnRequestsSigned;

   public SamlExternalIdentityProvider(String entityId, IDPSSODescriptorType IDPSSODescriptor)
   {
      super(entityId, IDPSSODescriptor.getKeyDescriptor());

      wantAuthnRequestsSigned = IDPSSODescriptor.isWantAuthnRequestsSigned();

      services.put(SamlProfile.SINGLE_SIGN_ON, new SamlService(SamlProfile.SINGLE_SIGN_ON, IDPSSODescriptor.getSingleSignOnService()));
      services.put(SamlProfile.SINGLE_LOGOUT, new SamlService(SamlProfile.SINGLE_LOGOUT, IDPSSODescriptor.getSingleLogoutService()));
   }

   public SamlService getService(SamlProfile service)
   {
      return services.get(service);
   }

   public boolean isWantAuthnRequestsSigned()
   {
      return wantAuthnRequestsSigned;
   }

   public void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned)
   {
      this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
   }
}
