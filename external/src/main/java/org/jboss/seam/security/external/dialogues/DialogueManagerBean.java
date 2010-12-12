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
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.servlet.event.Destroyed;
import org.jboss.seam.servlet.event.Initialized;

/**
 * @author Marcel Kolsteren
 * 
 */
public class DialogueManagerBean implements DialogueManager
{
   @Inject
   private DialogueContextExtension dialogueContextExtension;

   @Inject
   private Instance<DialogueBean> dialogue;

   public void servletInitialized(@Observes @Initialized final ServletContext context)
   {
      dialogueContextExtension.getDialogueContext().initialize(context);
   }

   public void servletDestroyed(@Observes @Destroyed final ServletContext context)
   {
      dialogueContextExtension.getDialogueContext().destroy();
   }

   public void beginDialogue()
   {
      String dialogueId = dialogueContextExtension.getDialogueContext().create();
      dialogue.get().setId(dialogueId);
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
      if (dialogue.get().isFinished())
      {
         endDialogue();
      }
      else
      {
         dialogueContextExtension.getDialogueContext().detach();
      }
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
