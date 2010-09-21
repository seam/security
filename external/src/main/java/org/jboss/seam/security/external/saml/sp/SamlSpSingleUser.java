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

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.SamlMultiUserServiceProviderApi;
import org.jboss.seam.security.external.api.SamlServiceProviderApi;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlSpSingleUser implements SamlServiceProviderApi
{
   @Inject
   private Instance<SamlMultiUserServiceProviderApi> multiUserApi;

   public void login(String idpEntityId, HttpServletResponse response)
   {
      multiUserApi.get().login(idpEntityId, response);
   }

   public void localLogout()
   {
      SamlSpSession session = getSession();
      if (session == null)
      {
         throw new IllegalStateException("Logout not possible because there is no current session.");
      }
      multiUserApi.get().localLogout(session);
   }

   public void globalLogout(HttpServletResponse response)
   {
      SamlSpSession session = getSession();
      if (session == null)
      {
         throw new IllegalStateException("Logout not possible because there is no current session.");
      }
      multiUserApi.get().globalLogout(session, response);
   }

   public SamlSpSession getSession()
   {
      if (multiUserApi.get().getSessions().size() == 0)
      {
         return null;
      }
      else
      {
         return multiUserApi.get().getSessions().iterator().next();
      }
   }
}
