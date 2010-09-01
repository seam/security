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

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import javax.enterprise.inject.Model;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

import org.jboss.seam.security.external.api.SamlEntityConfigurationApi;
import org.jboss.seam.security.external.saml.SamlExternalEntity;

@Model
public class Configuration
{
   private String spMetaDataUrl;

   @Inject
   private SamlEntityConfigurationApi samlEntityConfig;

   public String getSpMetaDataUrl()
   {
      return spMetaDataUrl;
   }

   public void setSpMetaDataUrl(String spMetaDataUrl)
   {
      this.spMetaDataUrl = spMetaDataUrl;
   }

   public void addSamlServiceProvider()
   {
      try
      {
         URL url = new URL(spMetaDataUrl);
         URLConnection urlConnection = url.openConnection();
         urlConnection.setConnectTimeout(3000);
         urlConnection.setReadTimeout(3000);
         Reader reader = new InputStreamReader(urlConnection.getInputStream());
         SamlExternalEntity samlEntity = samlEntityConfig.addExternalSamlEntity(reader);

         FacesMessage facesMessage = new FacesMessage("SAML entity " + samlEntity.getEntityId() + " has been added.");
         FacesContext.getCurrentInstance().addMessage(null, facesMessage);
      }
      catch (MalformedURLException e)
      {
         FacesMessage facesMessage = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Malformed URL.", "");
         FacesContext.getCurrentInstance().addMessage(null, facesMessage);
      }
      catch (IOException e)
      {
         FacesMessage facesMessage = new FacesMessage(FacesMessage.SEVERITY_ERROR, "Metadata could not be read.", "");
         FacesContext.getCurrentInstance().addMessage(null, facesMessage);
      }
   }

   public String getMetaDataUrl()
   {
      return samlEntityConfig.getMetaDataURL();
   }
}
