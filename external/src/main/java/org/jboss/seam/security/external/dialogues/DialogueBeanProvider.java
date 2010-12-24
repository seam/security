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

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.solder.beanManager.BeanManagerLocator;

/**
 * Provides dialogue beans to classes that are not able to inject.
 * 
 * @author Marcel Kolsteren
 * 
 */
public class DialogueBeanProvider
{
   public static Dialogue dialogue(ServletContext servletContext)
   {
      BeanManager beanManager = new BeanManagerLocator().getBeanManager();
      Bean<?> bean = beanManager.resolve(beanManager.getBeans(Dialogue.class));
      return (Dialogue) beanManager.getReference(bean, Dialogue.class, beanManager.createCreationalContext(bean));
   }

   public static DialogueManager dialogueManager(ServletContext servletContext)
   {
      BeanManager beanManager = new BeanManagerLocator().getBeanManager();
      Bean<?> bean = beanManager.resolve(beanManager.getBeans(DialogueManager.class));
      return (DialogueManager) beanManager.getReference(bean, DialogueManager.class, beanManager.createCreationalContext(bean));
   }
}
