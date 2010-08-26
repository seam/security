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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import javax.servlet.ServletRequest;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlRedirectMessage extends SamlMessage
{
   // Query string parameters used by the HTTP_Redirect binding
   public static final String QSP_SIGNATURE = "Signature";
   public static final String QSP_SIG_ALG = "SigAlg";
   public static final String QSP_RELAY_STATE = "RelayState";

   private String signature;

   private String signatureAlgorithm;

   private String relayState;

   // If this is true, the samlMessage, signature, signatureAlgorithm and
   // relayState values are in url encoded form
   private boolean urlEncoded;

   public SamlRedirectMessage()
   {
   }

   public SamlRedirectMessage(SamlRequestOrResponse samlRequestOrResponse, ServletRequest request)
   {
      this.samlRequestOrResponse = samlRequestOrResponse;
      if (samlRequestOrResponse.isRequest())
      {
         samlMessage = request.getParameter(SamlRedirectMessage.QSP_SAML_REQUEST);
      }
      else
      {
         samlMessage = request.getParameter(SamlRedirectMessage.QSP_SAML_RESPONSE);
      }
      relayState = request.getParameter(SamlRedirectMessage.QSP_RELAY_STATE);
      signatureAlgorithm = request.getParameter(SamlRedirectMessage.QSP_SIG_ALG);
      signature = request.getParameter(SamlRedirectMessage.QSP_SIGNATURE);
      urlEncoded = true;
   }

   public String createQueryString()
   {
      if (!urlEncoded)
      {
         encode();
      }
      StringBuilder queryString = new StringBuilder();
      if (samlRequestOrResponse.isRequest())
      {
         addParamToQueryString(queryString, SamlRedirectMessage.QSP_SAML_REQUEST, samlMessage);
      }
      else
      {
         addParamToQueryString(queryString, SamlRedirectMessage.QSP_SAML_RESPONSE, samlMessage);
      }
      addParamToQueryString(queryString, SamlRedirectMessage.QSP_RELAY_STATE, relayState);
      addParamToQueryString(queryString, SamlRedirectMessage.QSP_SIG_ALG, signatureAlgorithm);
      addParamToQueryString(queryString, SamlRedirectMessage.QSP_SIGNATURE, signature);

      return queryString.toString();
   }

   private void addParamToQueryString(StringBuilder queryString, String parameterName, String parameterValue)
   {
      if (parameterValue != null && parameterValue.length() != 0)
      {
         if (queryString.length() != 0)
         {
            queryString.append('&');
         }
         queryString.append(parameterName);
         queryString.append('=');
         queryString.append(parameterValue);
      }
   }

   public String getSignature()
   {
      return signature;
   }

   public void setSignature(String signature)
   {
      this.signature = signature;
   }

   public String getSignatureAlgorithm()
   {
      return signatureAlgorithm;
   }

   public void setSignatureAlgorithm(String signatureAlgorithm)
   {
      this.signatureAlgorithm = signatureAlgorithm;
   }

   public String getRelayState()
   {
      return relayState;
   }

   public void setRelayState(String relayState)
   {
      this.relayState = relayState;
   }

   public boolean isUrlEncoded()
   {
      return urlEncoded;
   }

   public void setUrlEncoded(boolean urlEncoded)
   {
      this.urlEncoded = urlEncoded;
   }

   public void encode()
   {
      if (!urlEncoded)
      {
         samlMessage = urlEncode(samlMessage);
         signature = urlEncode(signature);
         signatureAlgorithm = urlEncode(signatureAlgorithm);
         relayState = urlEncode(relayState);
         urlEncoded = true;
      }
   }

   public void decode()
   {
      if (urlEncoded)
      {
         samlMessage = urlDecode(samlMessage);
         signature = urlDecode(signature);
         signatureAlgorithm = urlDecode(signatureAlgorithm);
         relayState = urlDecode(relayState);
         urlEncoded = false;
      }
   }

   private String urlEncode(String value)
   {
      if (value == null)
      {
         return null;
      }
      try
      {
         return URLEncoder.encode(value, "UTF-8");
      }
      catch (UnsupportedEncodingException e)
      {
         throw new RuntimeException(e);
      }
   }

   private String urlDecode(String value)
   {
      if (value == null)
      {
         return null;
      }
      try
      {
         return URLDecoder.decode(value, "UTF-8");
      }
      catch (UnsupportedEncodingException e)
      {
         throw new RuntimeException(e);
      }
   }
}
