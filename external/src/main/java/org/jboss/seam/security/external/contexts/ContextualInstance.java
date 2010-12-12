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
package org.jboss.seam.security.external.contexts;

import javax.enterprise.context.spi.Contextual;
import javax.enterprise.context.spi.CreationalContext;

public class ContextualInstance<T> 
{
   private Contextual<T> contextual;

   private CreationalContext<T> creationalContext;

   private T instance;

   public ContextualInstance(Contextual<T> contextual, CreationalContext<T> creationalContext, T instance)
   {
      this.contextual = contextual;
      this.creationalContext = creationalContext;
      this.instance = instance;
   }

   public Contextual<T> getContextual()
   {
      return contextual;
   }

   public CreationalContext<T> getCreationalContext()
   {
      return creationalContext;
   }

   public T getInstance()
   {
      return instance;
   }

}
