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
package org.jboss.seam.security.external_authentication.configuration;

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
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.jboss.seam.security.external_authentication.jaxb.config.SamlConfigType;
import org.jboss.seam.security.external_authentication.jaxb.config.SamlIdentityProviderType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.metadata.EntitiesDescriptorType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.metadata.EntityDescriptorType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.metadata.IDPSSODescriptorType;
import org.jboss.seam.security.external_authentication.jaxb.samlv2.metadata.RoleDescriptorType;

public class SamlConfiguration
{
   private static final String SAML_ENTITIES_FILE = "/saml-entities.xml";

   private Map<String, IDPSSODescriptorType> idpMetaInfo = new HashMap<String, IDPSSODescriptorType>();

   private String entityId;

   private SamlIdentityProvider defaultIdentityProvider;

   private List<SamlIdentityProvider> identityProviders = new LinkedList<SamlIdentityProvider>();

   private boolean authnRequestsSigned = false;

   private boolean wantAssertionsSigned = false;

   private PrivateKey privateKey;

   private X509Certificate certificate;

   public SamlConfiguration(SamlConfigType samlConfig)
   {
      readSamlMetaInformation();

      this.entityId = samlConfig.getServiceProviderEntityId();
      this.authnRequestsSigned = samlConfig.isAuthnRequestsSigned();
      this.wantAssertionsSigned = samlConfig.isWantAssertionsSigned();

      for (SamlIdentityProviderType samlIdp : samlConfig.getSamlIdentityProvider())
      {
         IDPSSODescriptorType idpSsoDescriptor = idpMetaInfo.get(samlIdp.getEntityId());
         if (idpSsoDescriptor == null)
         {
            throw new RuntimeException("Saml identity provider with entity id \"" + samlIdp.getEntityId() + "\" not found in metadata.");
         }
         SamlIdentityProvider samlIdentityProvider = new SamlIdentityProvider(samlIdp.getEntityId(), idpSsoDescriptor);
         identityProviders.add(samlIdentityProvider);

         samlIdentityProvider.setWantSingleLogoutMessagesSigned(samlIdp.isWantSingleLogoutMessagesSigned());
         samlIdentityProvider.setSingleLogoutMessagesSigned(samlIdp.isSingleLogoutMessagesSigned());
      }

      boolean wantAuthnRequestsSigned = false;

      for (SamlIdentityProvider identityProvider : identityProviders)
      {
         if (identityProvider instanceof SamlIdentityProvider)
         {
            if (((SamlIdentityProvider) identityProvider).isWantAuthnRequestsSigned())
            {
               wantAuthnRequestsSigned = true;
            }
         }
         if (identityProvider.getEntityId().equals(samlConfig.getDefaultIdentityProvider()))
         {
            defaultIdentityProvider = identityProvider;
         }
      }

      if (wantAuthnRequestsSigned && !samlConfig.isAuthnRequestsSigned())
      {
         throw new RuntimeException("Configuration error: at least one identity provider wants the authentication requests signed, but the service provider doesn't sign authentication requests.");
      }

      String keyStoreUrl = samlConfig.getKeyStoreUrl();
      String keyStorePass = samlConfig.getKeyStorePass();
      String signingKeyAlias = samlConfig.getSigningKeyAlias();
      String signingKeyPass = samlConfig.getSigningKeyPass();
      if (signingKeyPass == null)
      {
         signingKeyPass = keyStorePass;
      }

      getSigningKeyPair(keyStoreUrl, keyStorePass, signingKeyAlias, signingKeyPass);
   }

   private void readSamlMetaInformation()
   {
      try
      {
         JAXBContext jaxbContext = JAXBContext.newInstance("org.picketlink.identity.federation.saml.v2.metadata");
         Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
         JAXBElement<?> o = (JAXBElement<?>) unmarshaller.unmarshal(getClass().getResource(SAML_ENTITIES_FILE));
         EntitiesDescriptorType entitiesDescriptor = (EntitiesDescriptorType) o.getValue();
         readEntitiesDescriptor(entitiesDescriptor);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }

   private void readEntitiesDescriptor(EntitiesDescriptorType entitiesDescriptor)
   {
      for (Object object : entitiesDescriptor.getEntityDescriptorOrEntitiesDescriptor())
      {
         if (object instanceof EntityDescriptorType)
         {
            EntityDescriptorType entityDescriptor = (EntityDescriptorType) object;
            String entityId = entityDescriptor.getEntityID();

            for (RoleDescriptorType roleDescriptor : entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor())
            {
               if (roleDescriptor instanceof IDPSSODescriptorType)
               {
                  IDPSSODescriptorType IDPSSODescriptor = (IDPSSODescriptorType) roleDescriptor;
                  idpMetaInfo.put(entityId, IDPSSODescriptor);
               }
            }
         }
         else
         {
            EntitiesDescriptorType descriptor = (EntitiesDescriptorType) object;
            readEntitiesDescriptor(descriptor);
         }
      }
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
            keyStoreStream = getClass().getClassLoader().getResourceAsStream(keyStoreUrl.substring(classPathPrefix.length()));
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

   public String getEntityId()
   {
      return entityId;
   }

   public SamlIdentityProvider getDefaultIdentityProvider()
   {
      return defaultIdentityProvider;
   }

   public List<SamlIdentityProvider> getIdentityProviders()
   {
      return identityProviders;
   }

   public boolean isAuthnRequestsSigned()
   {
      return authnRequestsSigned;
   }

   public boolean isWantAssertionsSigned()
   {
      return wantAssertionsSigned;
   }

   public PrivateKey getPrivateKey()
   {
      return privateKey;
   }

   public X509Certificate getCertificate()
   {
      return certificate;
   }

   public SamlIdentityProvider getSamlIdentityProviderByEntityId(String entityId)
   {
      for (SamlIdentityProvider identityProvider : identityProviders)
      {
         if (identityProvider instanceof SamlIdentityProvider)
         {
            SamlIdentityProvider samlIdentityProvider = (SamlIdentityProvider) identityProvider;
            if (samlIdentityProvider.getEntityId().equals(entityId))
            {
               return samlIdentityProvider;
            }
         }
      }
      return null;
   }
}
