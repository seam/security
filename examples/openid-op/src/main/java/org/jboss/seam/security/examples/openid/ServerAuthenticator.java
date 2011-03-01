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

import java.io.Serializable;

import javax.enterprise.inject.Model;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.openid.api.OpenIdProviderApi;

@Model
public class ServerAuthenticator extends BaseAuthenticator implements Authenticator, Serializable
{
   @Inject
   private OpenIdProviderApi providerApi;
   

   private String userNameReceivedFromRp;

   private String realm;

   @Inject
   private DialogueManager dialogueManager;

   @Inject
   private Identity identity;
   
   @Inject
   Credentials credentials;


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

   public void authenticate() {
       String userName = userNameReceivedFromRp != null ? userNameReceivedFromRp : credentials.getUsername();

       LocalUser user = new LocalUser();
       user.setUserName(userName);
       user.setOpLocalIdentifier(providerApi.getOpLocalIdentifierForUserName(userName));
       
       if (user != null) {
           setUser(user);
           
           if (dialogueManager.isAttached())
           {
               providerApi.authenticationSucceeded(userName, (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
           }
           setStatus(AuthenticationStatus.SUCCESS);
           return;
       }
       setStatus(AuthenticationStatus.FAILURE);
   }
   
   public void cancel()
   {
      if (dialogueManager.isAttached())
      {
          providerApi.authenticationFailed((HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
      }
      else
      {
         throw new IllegalStateException("cancel method can only be called during an OpenID login");
      }
   }

    public void redirectToLoginIfNotLoggedIn() {
        if (!identity.isLoggedIn()) {
            redirectToViewId("/Login.xhtml");
        }
    }

    private void redirectToViewId(String viewId) {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        FacesContext.getCurrentInstance().getApplication().getNavigationHandler()
                .handleNavigation(facesContext, null, viewId + "?faces-redirect=true");
    }
}
