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
package org.jboss.seam.security.externaltest.integration.saml.sp;

import java.io.IOException;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.api.SamlMultiUserServiceProviderApi;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.sp.SamlSpSession;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;
import org.slf4j.Logger;

@VirtualApplicationScoped
public class SamlSpApplicationMock implements SamlServiceProviderSpi
{
   @Inject
   private Instance<SamlMultiUserServiceProviderApi> spApi;

   @Inject
   private Logger log;

   @Dialogued
   public void login(String idpEntityId, HttpServletResponse response)
   {
      spApi.get().login(idpEntityId, response);
   }

   public void loginFailed(ResponseHolder responseHolder)
   {
      writeMessageToResponse("login failed", responseHolder);
   }

   public void loginSucceeded(SamlSpSession session, ResponseHolder responseHolder)
   {
      writeMessageToResponse("Login succeeded (" + session.getPrincipal().getNameId().getValue() + ")", responseHolder);
   }

   public void globalLogoutFailed(String statusCode, ResponseHolder responseHolder)
   {
      writeMessageToResponse("Single logout failed", responseHolder);
   }

   public void globalLogoutSucceeded(ResponseHolder responseHolder)
   {
      writeMessageToResponse("Single logout succeeded", responseHolder);
   }

   public void loggedIn(SamlSpSession session, String url, ResponseHolder responseHolder)
   {
      writeMessageToResponse("Logged in unsolicited", responseHolder);
   }

   private void writeMessageToResponse(String message, ResponseHolder responseHolder)
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
      return spApi.get().getSessions().size();
   }

   @Dialogued
   public void handleGlobalLogout(HttpServletResponse response)
   {
      SamlSpSession session = spApi.get().getSessions().iterator().next();
      spApi.get().globalLogout(session, response);
   }

   public void loggedOut(SamlSpSession session)
   {
      log.info("User " + session.getPrincipal().getNameId() + " has been logged out.");
   }
}
