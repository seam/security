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

public class SamlConstants
{
   // Query string parameters used by the HTTP_Redirect binding
   public static final String QSP_SAML_REQUEST = "SAMLRequest";

   public static final String QSP_SAML_RESPONSE = "SAMLResponse";

   public static final String QSP_SIGNATURE = "Signature";

   public static final String QSP_SIG_ALG = "SigAlg";

   public static final String QSP_RELAY_STATE = "RelayState";

   public static final String HTTP_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

   public static final String HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

   public static final String CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

   public static final String VERSION_2_0 = "2.0";

   public static final String PROTOCOL_NSURI = "urn:oasis:names:tc:SAML:2.0:protocol";

   public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

   public static final String XMLDSIG_NSURI = "http://www.w3.org/2000/09/xmldsig#";

   public static final String SIGNATURE_SHA1_WITH_DSA = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

   public static final String SIGNATURE_SHA1_WITH_RSA = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

   public static final String DSA_SIGNATURE_ALGORITHM = "SHA1withDSA";

   public static final String RSA_SIGNATURE_ALGORITHM = "SHA1withRSA";

}
