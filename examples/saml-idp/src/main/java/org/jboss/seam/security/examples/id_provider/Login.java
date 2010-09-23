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
package org.jboss.seam.security.examples.id_provider;

import javax.enterprise.inject.Model;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;

@Model
public class Login
{
   @Inject
   private SamlIdentityProviderApi samlIdentityProviderApi;

   private String userName;

   private String dialogueId;

   @Inject
   private DialogueManager dialogueManager;

   @Inject
   private Identity identity;

   @Inject
   private ExternalContext externalContext;

   public String getUserName()
   {
      return userName;
   }

   public void setUserName(String userName)
   {
      this.userName = userName;
   }

   public String getDialogueId()
   {
      return dialogueId;
   }

   public void setDialogueId(String dialogueId)
   {
      this.dialogueId = dialogueId;
   }

   public String login()
   {
      identity.localLogin(userName);
      if (dialogueId != null)
      {
         dialogueManager.attachDialogue(dialogueId);
         samlIdentityProviderApi.authenticationSucceeded((HttpServletResponse) externalContext.getResponse());
         dialogueManager.detachDialogue();
         return "SAML_LOGIN";
      }
      else
      {
         return "LOCAL_LOGIN";
      }
   }

   public void cancel()
   {
      if (dialogueId != null)
      {
         dialogueManager.attachDialogue(dialogueId);
         samlIdentityProviderApi.authenticationFailed((HttpServletResponse) externalContext.getResponse());
         dialogueManager.detachDialogue();
      }
      else
      {
         throw new IllegalStateException("cancel method can only be called during a SAML login");
      }
   }
}
