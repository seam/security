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
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlSigningKey
{
   private PrivateKey privateKey;

   private X509Certificate certificate;

   public SamlSigningKey(String keyStoreUrl, String keyStorePass, String signingKeyAlias, String signingKeyPass)
   {
      if (signingKeyPass == null)
      {
         signingKeyPass = keyStorePass;
      }
      getSigningKeyPair(keyStoreUrl, keyStorePass, signingKeyAlias, signingKeyPass);
   }

   private void getSigningKeyPair(String keyStoreUrl, String keyStorePass, String signingKeyAlias, String signingKeyPass)
   {
      final String classPathPrefix = "classpath:";

      try
      {
         KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
         InputStream keyStoreStream;
         if (keyStoreUrl.startsWith(classPathPrefix))
         {
            keyStoreStream = getClass().getResourceAsStream(keyStoreUrl.substring(classPathPrefix.length()));
            if (keyStoreStream == null)
            {
               throw new RuntimeException("Keystore " + keyStoreUrl + " could not be loaded from the classpath.");
            }
         }
         else
         {
            keyStoreStream = new URL(keyStoreUrl).openStream();
         }
         char[] keyStorePwd = keyStorePass != null ? keyStorePass.toCharArray() : null;
         keyStore.load(keyStoreStream, keyStorePwd);

         certificate = (X509Certificate) keyStore.getCertificate(signingKeyAlias);

         char[] signingKeyPwd = signingKeyPass != null ? signingKeyPass.toCharArray() : null;

         privateKey = (PrivateKey) keyStore.getKey(signingKeyAlias, signingKeyPwd);

         if (privateKey == null)
         {
            throw new RuntimeException("Key with alias " + signingKeyAlias + " was not found in keystore " + keyStoreUrl);
         }
      }
      catch (KeyStoreException e)
      {
         throw new RuntimeException(e);
      }
      catch (NoSuchAlgorithmException e)
      {
         throw new RuntimeException(e);
      }
      catch (CertificateException e)
      {
         throw new RuntimeException(e);
      }
      catch (MalformedURLException e)
      {
         throw new RuntimeException(e);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
      catch (UnrecoverableKeyException e)
      {
         throw new RuntimeException(e);
      }
   }

   public PrivateKey getPrivateKey()
   {
      return privateKey;
   }

   public X509Certificate getCertificate()
   {
      return certificate;
   }
}
