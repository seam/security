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

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;

/**
 * @author Marcel Kolsteren
 * 
 */
public class OpenIdMessageHandler
{
   @Inject
   private OpenIdSingleLoginReceiver openIdSingleLoginReceiver;

   @Inject
   private OpenIdXrdsProvider openIdXrdsProvider;

   @Inject
   private ResponseHandler responseHolder;

   public void handleMessage(HttpServletRequest httpRequest) throws InvalidRequestException
   {
      OpenIdService service = determineService(httpRequest);

      switch (service)
      {
      case OPEN_ID_SERVICE:
         openIdSingleLoginReceiver.handleIncomingMessage(httpRequest);
         break;
      case OPEN_ID_XRDS_SERVICE:
         openIdXrdsProvider.writeMetaData(responseHolder.getWriter("application/xrds+xml"));
         break;
      default:
         throw new RuntimeException("Unsupported service " + service);
      }
   }

   private OpenIdService determineService(HttpServletRequest httpRequest)
   {
      String path = httpRequest.getRequestURI();

      for (OpenIdService service : OpenIdService.values())
      {
         if (path.contains(service.getName()))
         {
            return service;
         }
      }
      return null;
   }

   public void destroy()
   {
   }
}
