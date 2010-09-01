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
package org.jboss.seam.security.external.dialogues;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.jboss.seam.security.external.dialogues.api.Dialogued;

/**
 * @author Marcel Kolsteren
 * 
 */
@Dialogued
@Interceptor
public class DialoguedInterceptor
{
   @Inject
   private DialogueManager manager;

   @AroundInvoke
   public Object intercept(InvocationContext ctx) throws Exception
   {
      boolean joined;
      Object result;
      boolean join = ctx.getMethod().getAnnotation(Dialogued.class).join();

      if (!join || !manager.isAttached())
      {
         manager.beginDialogue();
         joined = false;
      }
      else
      {
         joined = true;
      }

      try
      {
         result = ctx.proceed();
      }
      catch (Exception e)
      {
         if (!joined)
         {
            manager.detachDialogue();
         }
         throw (e);
      }

      if (!joined)
      {
         manager.detachDialogue();
      }

      return result;
   }
}
