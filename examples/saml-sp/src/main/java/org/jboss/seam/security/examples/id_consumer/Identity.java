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
package org.jboss.seam.security.examples.id_consumer;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

import org.jboss.seam.security.external.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.sp.SamlSpSession;

@Model
public class Identity
{
   @Inject
   private SamlServiceProviderApi samlSpApi;

   @Dialogued
   public void login(String idpEntityId)
   {
      if (!isLoggedIn())
      {
         samlSpApi.login(idpEntityId);
      }
      else
      {
         FacesMessage facesMessage = new FacesMessage("Already logged in.");
         FacesContext.getCurrentInstance().addMessage(null, facesMessage);
      }
   }

   public void localLogout()
   {
      if (isLoggedIn())
      {
         if (samlSpApi.getSession() != null)
         {
            samlSpApi.localLogout();
         }
      }
      else
      {
         FacesMessage facesMessage = new FacesMessage("Not logged in.");
         FacesContext.getCurrentInstance().addMessage(null, facesMessage);
      }
   }

   public void globalLogout()
   {
      if (isLoggedIn())
      {
         if (samlSpApi.getSession() != null)
         {
            samlSpApi.globalLogout();
         }
      }
      else
      {
         FacesMessage facesMessage = new FacesMessage("Not logged in.");
         FacesContext.getCurrentInstance().addMessage(null, facesMessage);
      }
   }

   public boolean isLoggedIn()
   {
      return samlSpApi.getSession() != null;
   }

   public SamlSpSession getSamlSpSession()
   {
      return samlSpApi.getSession();
   }

   public void redirectToLoginIfNotLoggedIn()
   {
      if (!isLoggedIn())
      {
         redirectToViewId("/Login.xhtml");
      }
   }

   private void redirectToViewId(String viewId)
   {
      FacesContext facesContext = FacesContext.getCurrentInstance();
      FacesContext.getCurrentInstance().getApplication().getNavigationHandler().handleNavigation(facesContext, null, viewId + "?faces-redirect=true");
   }
}
