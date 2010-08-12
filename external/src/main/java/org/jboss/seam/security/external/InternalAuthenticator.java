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
package org.jboss.seam.security.external;

import java.security.Principal;
import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.events.LoginFailedEvent;
import org.jboss.seam.security.events.PostAuthenticateEvent;
import org.jboss.seam.security.external.configuration.ServiceProvider;

@Named("internalAuthenticator")
public class InternalAuthenticator
{
   @Inject
   private Identity identity;

   @Inject
   private ServiceProvider serviceProvider;

   @Inject
   private BeanManager beanManager;

   public boolean authenticate(Principal principal, HttpServletRequest httpRequest)
   {
      List<String> roles = new LinkedList<String>();
      Boolean internallyAuthenticated = null; // FIXME =
      // serviceProvider.getInternalAuthenticationMethod().invoke(principal,
      // roles);

      beanManager.fireEvent(new PostAuthenticateEvent());

      if (internallyAuthenticated)
      {
         // FIXME identity.acceptExternallyAuthenticatedPrincipal(principal);

         for (String role : roles)
         {
            // FIXME identity.addRole(role);
         }

         beanManager.fireEvent(new LoggedInEvent(null) /* FIXME: no user */);
      }
      else
      {
         beanManager.fireEvent(new LoginFailedEvent(new LoginException()));
      }

      return internallyAuthenticated;
   }
}
