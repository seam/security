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

import org.jboss.seam.security.external.DialogueFilter;
import org.jboss.seam.security.external.dialogues.DialogueBeanProvider;
import org.jboss.seam.security.external.dialogues.api.Dialogue;

/**
 * @author Marcel Kolsteren
 * 
 */
public class DialogueAwareViewHandler extends ViewHandlerWrapper
{
   private static final String QUERY_STRING_DELIMITER = "?";
   private static final String PARAMETER_PAIR_DELIMITER = "&";
   private static final String PARAMETER_ASSIGNMENT_OPERATOR = "=";

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
         Dialogue dialogue = DialogueBeanProvider.dialogue(servletContext);
         return appendDialogueIdIfNecessary(actionUrl, facesContext, dialogue.getDialogueId());
      }
      else
      {
         return actionUrl;
      }
   }

   public String appendDialogueIdIfNecessary(String url, FacesContext facesContext, String cid)
   {
      String paramName = DialogueFilter.DIALOGUE_ID_PARAM;
      int queryStringIndex = url.indexOf(QUERY_STRING_DELIMITER);
      if (queryStringIndex < 0 || url.indexOf(paramName + PARAMETER_ASSIGNMENT_OPERATOR, queryStringIndex) < 0)
      {
         url = new StringBuilder(url).append(queryStringIndex < 0 ? QUERY_STRING_DELIMITER : PARAMETER_PAIR_DELIMITER).append(paramName).append(PARAMETER_ASSIGNMENT_OPERATOR).append(cid).toString();
      }
      return url;

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
