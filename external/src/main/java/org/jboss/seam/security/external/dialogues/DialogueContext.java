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

import java.util.UUID;

import javax.servlet.ServletContext;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;
import org.jboss.weld.context.AbstractMapContext;
import org.jboss.weld.context.api.BeanStore;
import org.jboss.weld.context.beanstore.HashMapBeanStore;

/**
 * @author Marcel Kolsteren
 * 
 */
public class DialogueContext extends AbstractMapContext
{
   private static final String BEAN_STORE_ATTRIBUTE_NAME_PREFIX = "DialogueContextBeanStore";
   private ServletContext servletContext;
   private final ThreadLocal<String> dialogueIdThreadLocal;

   public DialogueContext()
   {
      super(DialogueScoped.class);
      dialogueIdThreadLocal = new ThreadLocal<String>();
   }

   @Override
   protected BeanStore getBeanStore()
   {
      return getBeanStore(dialogueIdThreadLocal.get());
   }

   private BeanStore getBeanStore(String dialogueId)
   {
      BeanStore beanStore = (BeanStore) servletContext.getAttribute(getAttributeName(dialogueId));
      return beanStore;
   }

   private void createBeanStore(String dialogueId)
   {
      BeanStore beanStore = new HashMapBeanStore();
      servletContext.setAttribute(getAttributeName(dialogueId), beanStore);
   }

   private void removeBeanStore(String dialogueId)
   {
      servletContext.removeAttribute(getAttributeName(dialogueId));
   }

   private String getAttributeName(String dialogueId)
   {
      return BEAN_STORE_ATTRIBUTE_NAME_PREFIX + "_" + dialogueId;
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

   public String create()
   {
      if (this.dialogueIdThreadLocal.get() != null)
      {
         throw new RuntimeException("Already attached to a dialogue");
      }

      String dialogueId;
      do
      {
         dialogueId = UUID.randomUUID().toString();
      }
      while (getBeanStore(dialogueId) != null);

      this.dialogueIdThreadLocal.set(dialogueId);
      createBeanStore(dialogueId);
      setActive(true);
      return dialogueId;
   }

   public void remove()
   {
      removeBeanStore(this.dialogueIdThreadLocal.get());
      this.dialogueIdThreadLocal.set(null);
      setActive(false);
   }

   public boolean isExistingDialogue(String dialogueId)
   {
      return getBeanStore(dialogueId) != null;
   }

   /**
    * Attaches an existing request to the current thread
    * 
    * @param dialogueIdThreadLocal
    */
   public void attach(String dialogueId)
   {
      if (this.dialogueIdThreadLocal.get() != null)
      {
         throw new RuntimeException("Already attached to a dialogue");
      }
      if (!isExistingDialogue(dialogueId))
      {
         throw new RuntimeException("There is no active context with request id " + dialogueId);
      }
      this.dialogueIdThreadLocal.set(dialogueId);
      setActive(true);
   }

   /**
    * Detaches the request from the current thread
    */
   public void detach()
   {
      this.dialogueIdThreadLocal.set(null);
      setActive(false);
   }

   public boolean isAttached()
   {
      return dialogueIdThreadLocal.get() != null;
   }
}
