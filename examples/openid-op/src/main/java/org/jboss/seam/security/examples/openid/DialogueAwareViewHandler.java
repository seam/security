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
package org.jboss.seam.security.examples.openid;

import javax.faces.application.ViewHandler;
import javax.faces.application.ViewHandlerWrapper;
import javax.faces.context.FacesContext;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.ResponseHolderImpl;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.DialogueBeanProvider;

/**
 * @author Marcel Kolsteren
 * 
 */
public class DialogueAwareViewHandler extends ViewHandlerWrapper
{
   private ViewHandler delegate;

   public DialogueAwareViewHandler(ViewHandler delegate)
   {
      this.delegate = delegate;
   }

   @Override
   public String getActionURL(FacesContext facesContext, String viewId)
   {
      String actionUrl = super.getActionURL(facesContext, viewId);
      ServletContext servletContext = (ServletContext) facesContext.getExternalContext().getContext();
      if (DialogueBeanProvider.dialogueManager(servletContext).isAttached())
      {
         String dialogueId = DialogueBeanProvider.dialogue(servletContext).getDialogueId();
         ResponseHolder responseHolder = new ResponseHolderImpl((HttpServletResponse) facesContext.getExternalContext().getResponse(), dialogueId);
         return responseHolder.addDialogueIdToUrl(actionUrl);
      }
      else
      {
         return actionUrl;
      }
   }

   /**
    * @see {@link ViewHandlerWrapper#getWrapped()}
    */
   @Override
   public ViewHandler getWrapped()
   {
      return delegate;
   }

}
