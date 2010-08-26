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

import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.ServletContextEvent;

import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.servlet.event.qualifier.Destroyed;
import org.jboss.seam.servlet.event.qualifier.Initialized;

/**
 * @author Marcel Kolsteren
 * 
 */
public class DialogueContextManagerImpl implements DialogueManager
{
   @Inject
   private DialogueContextExtension dialogueContextExtension;

   @Inject
   private Instance<Dialogue> dialogue;

   protected void servletInitialized(@Observes @Initialized final ServletContextEvent e)
   {
      dialogueContextExtension.getDialogueContext().initialize(e.getServletContext());
   }

   protected void servletDestroyed(@Observes @Destroyed final ServletContextEvent e)
   {
      dialogueContextExtension.getDialogueContext().destroy();
   }

   public void beginDialogue()
   {
      String dialogueId = dialogueContextExtension.getDialogueContext().create();
      dialogue.get().setDialogueId(dialogueId);
   }

   public void endDialogue()
   {
      dialogueContextExtension.getDialogueContext().remove();
   }

   public void attachDialogue(String requestId)
   {
      dialogueContextExtension.getDialogueContext().attach(requestId);
   }

   public void detachDialogue()
   {
      dialogueContextExtension.getDialogueContext().detach();
   }

   public boolean isExistingDialogue(String dialogueId)
   {
      return dialogueContextExtension.getDialogueContext().isExistingDialogue(dialogueId);
   }

   public boolean isAttached()
   {
      return dialogueContextExtension.getDialogueContext().isAttached();
   }
}
