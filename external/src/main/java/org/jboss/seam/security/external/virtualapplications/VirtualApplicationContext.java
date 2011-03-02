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
package org.jboss.seam.security.external.virtualapplications;

import java.lang.annotation.Annotation;

import javax.enterprise.context.ContextNotActiveException;
import javax.enterprise.context.spi.Context;
import javax.enterprise.context.spi.Contextual;
import javax.enterprise.context.spi.CreationalContext;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.contexts.ContextualInstance;
import org.jboss.seam.security.external.contexts.HashMapBeanStore;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * @author Marcel Kolsteren
 * 
 */
public class VirtualApplicationContext implements Context
{
   private static final String BEAN_STORE_ATTRIBUTE_NAME_PREFIX = "virtualApplicationContextBeanStore";

   private ServletContext servletContext;

   private final ThreadLocal<String> hostNameThreadLocal;

   public VirtualApplicationContext()
   {
      hostNameThreadLocal = new ThreadLocal<String>();
   }

   protected HashMapBeanStore getBeanStore()
   {
      return getBeanStore(hostNameThreadLocal.get());
   }

   private HashMapBeanStore getBeanStore(String hostName)
   {
      HashMapBeanStore beanStore = (HashMapBeanStore) servletContext.getAttribute(getAttributeName(hostName));
      return beanStore;
   }

   private void createBeanStore(String hostName)
   {
      HashMapBeanStore beanStore = new HashMapBeanStore();
      servletContext.setAttribute(getAttributeName(hostName), beanStore);
   }

   private void removeBeanStore(String hostName)
   {
      servletContext.removeAttribute(getAttributeName(hostName));
   }

   private String getAttributeName(String hostName)
   {
      return BEAN_STORE_ATTRIBUTE_NAME_PREFIX + "_" + hostName;
   }

   public void initialize(ServletContext servletContext)
   {
      this.servletContext = servletContext;
   }

   public void destroy()
   {
      this.servletContext = null;
   }

   public void create(String hostName)
   {
      createBeanStore(hostName);
      attach(hostName);
   }

   public void remove()
   {
      getBeanStore().clear();
      removeBeanStore(this.hostNameThreadLocal.get());
      detach();
   }

   public boolean isExistingVirtualApplication(String hostName)
   {
      return servletContext != null && getBeanStore(hostName) != null;
   }

   public void attach(String hostName)
   {
      this.hostNameThreadLocal.set(hostName);
   }

   public void detach()
   {
      this.hostNameThreadLocal.set(null);
   }

   public <T> T get(Contextual<T> contextual, CreationalContext<T> creationalContext)
   {
      if (!isActive())
      {
         throw new ContextNotActiveException();
      }
      ContextualInstance<T> beanInstance = getBeanStore().get(contextual);
      if (beanInstance != null)
      {
         return beanInstance.getInstance();
      }
      else if (creationalContext != null)
      {
         T instance = contextual.create(creationalContext);
         if (instance != null)
         {
            beanInstance = new ContextualInstance<T>(contextual, creationalContext, instance);
            getBeanStore().put(contextual, beanInstance);
         }
         return instance;
      }
      else
      {
         return null;
      }
   }

   public <T> T get(Contextual<T> contextual)
   {
      return get(contextual, null);
   }

   public Class<? extends Annotation> getScope()
   {
      return VirtualApplicationScoped.class;
   }

   public boolean isActive()
   {
      return hostNameThreadLocal.get() != null;
   }
}
