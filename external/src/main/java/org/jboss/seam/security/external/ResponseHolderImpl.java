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
package org.jboss.seam.security.external;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.DialogueFilter;

/**
 * @author Marcel Kolsteren
 * 
 */
public class ResponseHolderImpl implements ResponseHolder
{
   private HttpServletResponse response;

   private String dialogueId;

   public ResponseHolderImpl(HttpServletResponse response, String dialogueId)
   {
      this.response = response;
      this.dialogueId = dialogueId;
   }

   public HttpServletResponse getResponse()
   {
      return response;
   }

   public void setResponse(HttpServletResponse response)
   {
      this.response = response;
   }

   public void redirectWithDialoguePropagation(String url)
   {
      if (dialogueId != null)
      {
         url = addDialogueIdToUrl(url);
      }
      String encodedUrl = response.encodeURL(url);
      try
      {
         response.sendRedirect(encodedUrl);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public String addDialogueIdToUrl(String url)
   {
      String paramName = DialogueFilter.DIALOGUE_ID_PARAM;
      int queryStringIndex = url.indexOf("?");
      if (queryStringIndex < 0 || url.indexOf(paramName + "=", queryStringIndex) < 0)
      {
         url = new StringBuilder(url).append(queryStringIndex < 0 ? "?" : "&").append(paramName).append("=").append(dialogueId).toString();
      }
      return url;
   }
}
