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

import java.io.Serializable;

import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;

@Named
public class Identity implements Serializable
{
   private static final long serialVersionUID = 3739296115750412807L;

   @Inject
   private SamlIdentityProviderApi samlIdp;

   public void localLogin(String userName)
   {
      samlIdp.localLogin(samlIdp.createNameId(userName, null, null), null);
   }

   public void remoteLogin(String spEntityId)
   {
      samlIdp.remoteLogin(spEntityId, null, (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
   }

   public void localLogout()
   {
      samlIdp.localLogout();
   }

   public void globalLogout()
   {
      samlIdp.globalLogout((HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
   }

   public boolean isLoggedIn()
   {
      return samlIdp.getSession() != null;
   }

   public void redirectToLoginIfNotLoggedIn()
   {
      if (!isLoggedIn())
      {
         redirectToViewId("/Login.xhtml");
      }
   }

   public SamlIdpSession getSamlIdpSession()
   {
      return samlIdp.getSession();
   }

   private void redirectToViewId(String viewId)
   {
      FacesContext facesContext = FacesContext.getCurrentInstance();
      FacesContext.getCurrentInstance().getApplication().getNavigationHandler().handleNavigation(facesContext, null, viewId + "?faces-redirect=true");
   }
}
