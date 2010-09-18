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

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.DialogueManager;

@WebFilter(filterName = "DialogueFilter", urlPatterns = "/*")
public class DialogueFilter implements Filter
{
   public final static String DIALOGUE_ID_PARAM = "dialogueId";

   @Inject
   private DialogueManager manager;

   @Inject
   private ResponseHolder responseHolder;

   public void init(FilterConfig filterConfig) throws ServletException
   {
   }

   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
   {
      responseHolder.setResponse((HttpServletResponse) response);

      if (manager.isAttached())
      {
         manager.detachDialogue();
      }

      String dialogueId = request.getParameter(DIALOGUE_ID_PARAM);

      if (dialogueId != null)
      {
         if (!manager.isExistingDialogue(dialogueId))
         {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST, "dialogue " + dialogueId + " does not exist");
            return;
         }
         manager.attachDialogue(dialogueId);
      }

      chain.doFilter(request, response);

      if (manager.isAttached())
      {
         manager.detachDialogue();
      }
   }

   public void destroy()
   {
   }
}
