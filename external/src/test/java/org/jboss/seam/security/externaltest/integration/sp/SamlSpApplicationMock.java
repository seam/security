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
package org.jboss.seam.security.externaltest.integration.sp;

import java.io.IOException;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.sp.SamlSpSession;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;
import org.slf4j.Logger;

@VirtualApplicationScoped
public class SamlSpApplicationMock implements SamlServiceProviderSpi
{
   @Inject
   private Instance<SamlServiceProviderApi> samlServiceProviderApi;

   @Inject
   private ResponseHolder responseHolder;

   @Inject
   private Logger log;

   @Dialogued
   public void login(String idpEntityId)
   {
      samlServiceProviderApi.get().signOn(idpEntityId);
   }

   public void loginFailed()
   {
      writeMessageToResponse("login failed");
   }

   public void loginSucceeded(SamlSpSession session)
   {
      writeMessageToResponse("Login succeeded (" + session.getPrincipal().getNameId().getValue() + ")");
   }

   public void singleLogoutFailed(String statusCode)
   {
      writeMessageToResponse("Single logout failed");
   }

   public void singleLogoutSucceeded()
   {
      writeMessageToResponse("Single logout succeeded");
   }

   public void unsolicitedLogin(SamlSpSession session)
   {
      writeMessageToResponse("Logged in unsolicited");
   }

   private void writeMessageToResponse(String message)
   {
      try
      {
         responseHolder.getResponse().getWriter().print(message);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public int getNumberOfSessions()
   {
      return samlServiceProviderApi.get().getSessions().size();
   }

   @Dialogued
   public void handleSingleLogout(String userName)
   {
      SamlSpSession session = null;
      for (SamlSpSession s : samlServiceProviderApi.get().getSessions())
      {
         if (s.getPrincipal().getNameId().getValue().equals(userName))
         {
            session = s;
         }
      }
      if (session != null)
      {
         samlServiceProviderApi.get().singleLogout(session);
      }
      else
      {
         throw new RuntimeException("No session found for user " + userName);
      }
   }

   public void loggedOut(SamlSpSession session)
   {
      log.info("User " + session.getPrincipal().getNameId() + " has been logged out.");
   }
}
