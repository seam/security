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
package org.jboss.seam.security.external.saml;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlServlet extends HttpServlet
{
   private static final long serialVersionUID = -6125510783395424719L;

   @Inject
   private Logger log;

   @Inject
   private SamlMessageReceiver samlMessageReceiver;

   @Inject
   private ResponseHandler responseHandler;

   @Inject
   private Instance<SamlEntityBean> samlEntityBean;

   @Override
   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      doGetOrPost(request, response);
   }

   @Override
   protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      doGetOrPost(request, response);
   }

   private void doGetOrPost(HttpServletRequest request, HttpServletResponse response) throws IOException
   {
      try
      {
         handleMessage(request, response);
      }
      catch (InvalidRequestException e)
      {
         response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getDescription());
         log.infof("Bad request received from %s: %s", request.getRemoteHost(), e.getDescription());
      }
   }

   private void handleMessage(HttpServletRequest httpRequest, HttpServletResponse response) throws InvalidRequestException
   {
      Matcher matcher = Pattern.compile("/(IDP|SP)/(.*?)$").matcher(httpRequest.getRequestURI());
      boolean found = matcher.find();
      if (!found)
      {
         responseHandler.sendError(HttpServletResponse.SC_NOT_FOUND, "No service endpoint exists for this URL.", response);
      }
      SamlIdpOrSp idpOrSp = SamlIdpOrSp.valueOf(matcher.group(1));
      SamlServiceType service = SamlServiceType.getByName(matcher.group(2));

      switch (service)
      {
      case SAML_SINGLE_LOGOUT_SERVICE:
      case SAML_SINGLE_SIGN_ON_SERVICE:
      case SAML_ASSERTION_CONSUMER_SERVICE:
         samlMessageReceiver.handleIncomingSamlMessage(service, httpRequest, response, idpOrSp);
         break;
      case SAML_META_DATA_SERVICE:
         samlEntityBean.get().writeMetaData(responseHandler.getWriter("application/xml", response));
         break;
      default:
         throw new RuntimeException("Unsupported service " + service);
      }
   }
}
