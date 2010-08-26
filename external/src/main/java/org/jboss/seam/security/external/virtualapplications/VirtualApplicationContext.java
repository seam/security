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

import javax.servlet.ServletContext;

import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;
import org.jboss.weld.context.AbstractMapContext;
import org.jboss.weld.context.api.BeanStore;
import org.jboss.weld.context.beanstore.HashMapBeanStore;

/**
 * @author Marcel Kolsteren
 * 
 */
public class VirtualApplicationContext extends AbstractMapContext
{
   private static final String BEAN_STORE_ATTRIBUTE_NAME_PREFIX = "virtualApplicationContextBeanStore";
   private ServletContext servletContext;
   private final ThreadLocal<String> hostNameThreadLocal;

   public VirtualApplicationContext()
   {
      super(VirtualApplicationScoped.class);
      hostNameThreadLocal = new ThreadLocal<String>();
   }

   @Override
   protected BeanStore getBeanStore()
   {
      return getBeanStore(hostNameThreadLocal.get());
   }

   private BeanStore getBeanStore(String hostName)
   {
      BeanStore beanStore = (BeanStore) servletContext.getAttribute(getAttributeName(hostName));
      return beanStore;
   }

   private BeanStore createBeanStore(String hostName)
   {
      BeanStore beanStore = new HashMapBeanStore();
      servletContext.setAttribute(getAttributeName(hostName), beanStore);
      return beanStore;
   }

   private void removeBeanStore(String hostName)
   {
      servletContext.removeAttribute(getAttributeName(hostName));
   }

   private String getAttributeName(String hostName)
   {
      return BEAN_STORE_ATTRIBUTE_NAME_PREFIX + "_" + hostName;
   }

   @Override
   protected boolean isCreationLockRequired()
   {
      // TODO: find out whether the creation lock is required
      return false;
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
      setActive(true);
   }

   public void detach()
   {
      this.hostNameThreadLocal.set(null);
      setActive(false);
   }
}
