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
package org.jboss.seam.security.external_authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.security.external_authentication.configuration.SamlIdentityProvider;
import org.jboss.seam.security.util.Base64;

public class SamlSignatureUtilForRedirectBinding
{
   byte[] computeSignature(String requestOrResponseKeyValuePair, PrivateKey signingKey) throws IOException, GeneralSecurityException
   {
      StringBuilder sb = new StringBuilder();
      sb.append(requestOrResponseKeyValuePair);
      String algo = signingKey.getAlgorithm();

      String sigAlg = getXMLSignatureAlgorithmURI(algo);
      sigAlg = URLEncoder.encode(sigAlg, "UTF-8");
      sb.append("&SigAlg=").append(sigAlg);

      byte[] sigValue = sign(sb.toString(), signingKey);

      return sigValue;
   }

   private byte[] sign(String stringToBeSigned, PrivateKey signingKey) throws GeneralSecurityException
   {
      String algo = signingKey.getAlgorithm();
      Signature sig = getSignature(algo);
      sig.initSign(signingKey);
      sig.update(stringToBeSigned.getBytes());
      return sig.sign();
   }

   public void validateSignature(SamlIdentityProvider idp, HttpServletRequest httpRequest, RequestOrResponse requestOrResponse) throws InvalidRequestException
   {
      String sigValueParam = httpRequest.getParameter(SamlConstants.QSP_SIGNATURE);
      if (sigValueParam == null)
      {
         throw new InvalidRequestException("Signature parameter is not present.");
      }

      String decodedString;
      try
      {
         decodedString = URLDecoder.decode(sigValueParam, "UTF-8");
      }
      catch (UnsupportedEncodingException e)
      {
         throw new RuntimeException(e);
      }

      byte[] sigValue = Base64.decode(decodedString);

      String samlMessageParameter;
      if (requestOrResponse == RequestOrResponse.REQUEST)
      {
         samlMessageParameter = SamlConstants.QSP_SAML_REQUEST;
      }
      else
      {
         samlMessageParameter = SamlConstants.QSP_SAML_RESPONSE;
      }

      // Construct the url again
      String reqFromURL = httpRequest.getParameter(samlMessageParameter);
      String relayStateFromURL = httpRequest.getParameter(SamlConstants.QSP_RELAY_STATE);
      String sigAlgFromURL = httpRequest.getParameter(SamlConstants.QSP_SIG_ALG);

      StringBuilder sb = new StringBuilder();
      sb.append(samlMessageParameter).append("=").append(reqFromURL);

      if (relayStateFromURL != null && relayStateFromURL.length() != 0)
      {
         sb.append("&").append(SamlConstants.QSP_RELAY_STATE).append("=").append(relayStateFromURL);
      }
      sb.append("&").append(SamlConstants.QSP_SIG_ALG).append("=").append(sigAlgFromURL);

      PublicKey validatingKey = idp.getPublicKey();

      boolean isValid;
      try
      {
         isValid = validate(sb.toString().getBytes("UTF-8"), sigValue, validatingKey);
      }
      catch (UnsupportedEncodingException e)
      {
         throw new RuntimeException(e);
      }
      catch (GeneralSecurityException e)
      {
         throw new RuntimeException(e);
      }

      if (!isValid)
      {
         throw new InvalidRequestException("Invalid signature.");
      }
   }

   private boolean validate(byte[] signedContent, byte[] signatureValue, PublicKey validatingKey) throws GeneralSecurityException
   {
      // We assume that the sigatureValue has the same algorithm as the public
      // key
      // If not, there will be an exception anyway
      String algo = validatingKey.getAlgorithm();
      Signature sig = getSignature(algo);

      sig.initVerify(validatingKey);
      sig.update(signedContent);
      return sig.verify(signatureValue);
   }

   private Signature getSignature(String algo) throws GeneralSecurityException
   {
      Signature sig = null;

      if ("DSA".equalsIgnoreCase(algo))
      {
         sig = Signature.getInstance(SamlConstants.DSA_SIGNATURE_ALGORITHM);
      }
      else if ("RSA".equalsIgnoreCase(algo))
      {
         sig = Signature.getInstance(SamlConstants.RSA_SIGNATURE_ALGORITHM);
      }
      else
         throw new RuntimeException("Unknown signature algorithm:" + algo);
      return sig;
   }

   public String getXMLSignatureAlgorithmURI(String algo)
   {
      String xmlSignatureAlgo = null;

      if ("DSA".equalsIgnoreCase(algo))
      {
         xmlSignatureAlgo = SamlConstants.SIGNATURE_SHA1_WITH_DSA;
      }
      else if ("RSA".equalsIgnoreCase(algo))
      {
         xmlSignatureAlgo = SamlConstants.SIGNATURE_SHA1_WITH_RSA;
      }
      return xmlSignatureAlgo;
   }
}