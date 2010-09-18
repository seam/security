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
package org.jboss.seam.security.external.openid;

import java.io.IOException;
import java.net.URLDecoder;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.spi.OpenIdProviderSpi;

/**
 * @author Marcel Kolsteren
 * 
 */
public class OpenIdUsersServlet extends HttpServlet
{
   private static final long serialVersionUID = 1476698956314628568L;

   @Inject
   private Instance<OpenIdProviderBean> opBean;

   @Inject
   private Instance<OpenIdProviderSpi> providerSpi;

   @Override
   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      String prefix = opBean.get().getUsersUrlPrefix();
      if (!request.getRequestURL().toString().startsWith(prefix))
      {
         response.sendError(HttpServletResponse.SC_NOT_FOUND, "Only accepting requests for URLs starting with " + prefix);
         return;
      }

      String userNamePart = request.getRequestURL().substring(prefix.length());
      String userName = URLDecoder.decode(userNamePart, "UTF-8");

      if (providerSpi.get().userExists(userName))
      {
         response.setContentType("application/xrds+xml");
         opBean.get().writeClaimedIdentifierXrds(response.getWriter(), opBean.get().getOpLocalIdentifierForUserName(userName));
      }
      else
      {
         response.sendError(HttpServletResponse.SC_NOT_FOUND, "User " + userName + " does not exist.");
      }
   }
}
