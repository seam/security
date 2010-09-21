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

import javax.enterprise.inject.Model;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.OpenIdProviderApi;
import org.jboss.seam.security.external.dialogues.DialogueManager;

@Model
public class Login
{
   @Inject
   private OpenIdProviderApi opApi;

   private String userNameReceivedFromRp;

   private String realm;

   private String userName;

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

   public String getUserNameReceivedFromRp()
   {
      return userNameReceivedFromRp;
   }

   public void setUserNameReceivedFromRp(String userNameReceivedFromRp)
   {
      this.userNameReceivedFromRp = userNameReceivedFromRp;
   }

   public String getRealm()
   {
      return realm;
   }

   public void setRealm(String realm)
   {
      this.realm = realm;
   }

   public boolean isDialogueActive()
   {
      return dialogueManager.isAttached();
   }

   public String login()
   {
      String userName = userNameReceivedFromRp != null ? userNameReceivedFromRp : this.userName;
      identity.localLogin(userName);
      if (dialogueManager.isAttached())
      {
         opApi.authenticationSucceeded(userName, (HttpServletResponse) externalContext.getResponse());
         return null;
      }
      else
      {
         return "LOCAL_LOGIN";
      }
   }

   public void cancel()
   {
      if (dialogueManager.isAttached())
      {
         opApi.authenticationFailed((HttpServletResponse) externalContext.getResponse());
      }
      else
      {
         throw new IllegalStateException("cancel method can only be called during an OpenID login");
      }
   }
}
