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

import java.util.HashMap;
import java.util.Map;

import javax.enterprise.context.spi.Contextual;

/**
 * Non-serializable bean store, based on a hash map. This bean store should not
 * be used for passivating scopes!
 * 
 * @author Marcel Kolsteren
 * 
 */
public class HashMapBeanStore
{
   private static final long serialVersionUID = -8676730520345382886L;

   protected Map<Contextual<?>, ContextualInstance<? extends Object>> contextualInstanceMap;

   public HashMapBeanStore()
   {
      contextualInstanceMap = new HashMap<Contextual<?>, ContextualInstance<? extends Object>>();
   }

   public <T extends Object> ContextualInstance<T> get(Contextual<T> contextual)
   {
      @SuppressWarnings("unchecked")
      ContextualInstance<T> instance = (ContextualInstance<T>) contextualInstanceMap.get(contextual);
      return instance;
   }

   private <T> void destroy(Contextual<T> contextual)
   {
      ContextualInstance<T> beanInstance = get(contextual);
      beanInstance.getContextual().destroy(beanInstance.getInstance(), beanInstance.getCreationalContext());
   }

   public void clear()
   {
      for (Contextual<?> contextual : contextualInstanceMap.keySet())
      {
         destroy(contextual);
      }
      contextualInstanceMap.clear();
   }

   public <T> void put(Contextual<T> contextual, ContextualInstance<T> beanInstance)
   {
      contextualInstanceMap.put(contextual, beanInstance);
   }
}
