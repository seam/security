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
package org.jboss.seam.security.examples.openid;

import javax.enterprise.event.Observes;
import javax.faces.event.PhaseEvent;
import javax.inject.Inject;

import org.jboss.seam.faces.event.qualifier.Before;
import org.jboss.seam.faces.event.qualifier.RestoreView;
import org.jboss.seam.security.external.dialogues.DialogueManager;
import org.jboss.seam.servlet.http.HttpParam;

public class DialoguePhaseListener
{
   private static final long serialVersionUID = -3608798865478624561L;

   public final static String DIALOGUE_ID_PARAM = "dialogueId";

   @Inject
   private DialogueManager manager;

   @Inject
   @HttpParam("dialogueId")
   private String dialogueId;

   public void beforeRestoreView(@Observes @Before @RestoreView PhaseEvent phaseEvent)
   {
      if (dialogueId != null && !manager.isAttached())
      {
         manager.attachDialogue(dialogueId);
      }
   }
}
