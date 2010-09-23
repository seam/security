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
package org.jboss.seam.security.external.dialogues.api;

/**
 * Manager for the dialogue scope. For background about the dialogue scope, see
 * {@link DialogueScoped}.
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface DialogueManager
{
   /**
    * Starts a new dialogue. Results in a {@link RuntimeException} if
    * {@link #isAttached} is true.
    */
   void beginDialogue();

   /**
    * Ends the current dialogue. Results in a {@link RuntimeException} if
    * {@link #isAttached} is false.
    */
   void endDialogue();

   /**
    * Checks whether a dialogue exists with the given id.
    * 
    * @param dialogueId the id
    * @return true if a dialogue with that id exists
    */
   boolean isExistingDialogue(String dialogueId);

   /**
    * Checks whether the current thread is attached to a dialogue (i.e. whether
    * a dialogue is currently active)
    * 
    * @return true if the current thread is attached to a dialogue
    */
   boolean isAttached();

   /**
    * Attaches the current thread to the given dialogue. Results in a
    * {@link RuntimeException} if the thread is already attached to a dialogue,
    * i.e. if {@link #isAttached} is true.
    * 
    * @param dialogueId
    */
   void attachDialogue(String dialogueId);

   /**
    * Detaches the current thread from the dialogue. Results in a
    * {@link RuntimeException} if {@link #isAttached} is false.
    */
   void detachDialogue();
}
