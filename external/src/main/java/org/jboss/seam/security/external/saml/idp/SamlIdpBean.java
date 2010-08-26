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
package org.jboss.seam.security.external.saml.idp;

import java.io.Reader;
import java.io.Writer;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.api.SamlNameId;
import org.jboss.seam.security.external.api.SamlPrincipal;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.EntityDescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IDPSSODescriptorType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.IndexedEndpointType;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.metadata.SPSSODescriptorType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlEntityBean;
import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.SamlIdpOrSp;
import org.jboss.seam.security.external.saml.SamlServiceType;

/**
 * @author Marcel Kolsteren
 * 
 */
@Typed(SamlIdpBean.class)
public class SamlIdpBean extends SamlEntityBean implements SamlIdentityProviderApi
{
   @Inject
   private SamlIdpSingleSignOnService samlIdpSingleSignOnService;

   @Inject
   private SamlIdpSingleLogoutService samlIdpSingleSignLogoutService;

   @Inject
   private SamlIdpSessions samlIdpSessions;

   private List<SamlExternalServiceProvider> serviceProviders = new LinkedList<SamlExternalServiceProvider>();

   // No boolean assertionsSigned: the identity provider always signs the
   // assertions.

   private boolean wantAuthnRequestsSigned = false;

   @Inject
   private Instance<SamlDialogue> samlDialogue;

   public List<SamlExternalServiceProvider> getServiceProviders()
   {
      return serviceProviders;
   }

   public SamlExternalServiceProvider addExternalServiceProvider(String entityId, SPSSODescriptorType spSsoDescriptor)
   {
      SamlExternalServiceProvider samlServiceProvider = new SamlExternalServiceProvider(entityId, spSsoDescriptor);
      serviceProviders.add(samlServiceProvider);
      return samlServiceProvider;
   }

   public SamlExternalServiceProvider addExternalSamlEntity(Reader reader)
   {
      EntityDescriptorType entityDescriptor = readEntityDescriptor(reader);
      String entityId = entityDescriptor.getEntityID();
      SPSSODescriptorType SPSSODescriptor = (SPSSODescriptorType) entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().get(0);
      return addExternalServiceProvider(entityId, SPSSODescriptor);
   }

   @Override
   public List<SamlExternalEntity> getExternalSamlEntities()
   {
      List<SamlExternalEntity> samlEntities = new LinkedList<SamlExternalEntity>();
      for (SamlExternalServiceProvider sp : serviceProviders)
      {
         samlEntities.add(sp);
      }
      return samlEntities;
   }

   public boolean isWantAuthnRequestsSigned()
   {
      return wantAuthnRequestsSigned;
   }

   public void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned)
   {
      this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
   }

   public SamlExternalServiceProvider getExternalSamlEntityByEntityId(String entityId)
   {
      for (SamlExternalServiceProvider serviceProvider : serviceProviders)
      {
         if (serviceProvider.getEntityId().equals(entityId))
         {
            return serviceProvider;
         }
      }
      return null;
   }

   public void writeMetaData(Writer writer)
   {
      try
      {
         ObjectFactory metaDataFactory = new ObjectFactory();

         IndexedEndpointType ssoRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
         ssoRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
         ssoRedirectEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_SINGLE_SIGN_ON_SERVICE));

         IndexedEndpointType ssoPostEndpoint = metaDataFactory.createIndexedEndpointType();
         ssoPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
         ssoPostEndpoint.setLocation(getServiceURL(SamlServiceType.SAML_SINGLE_SIGN_ON_SERVICE));

         IDPSSODescriptorType idpSsoDescriptor = metaDataFactory.createIDPSSODescriptorType();

         idpSsoDescriptor.getSingleSignOnService().add(ssoRedirectEndpoint);
         idpSsoDescriptor.getSingleSignOnService().add(ssoPostEndpoint);
         addSloEndpointsToMetaData(idpSsoDescriptor);

         idpSsoDescriptor.setWantAuthnRequestsSigned(isWantAuthnRequestsSigned());

         idpSsoDescriptor.getProtocolSupportEnumeration().add(SamlConstants.PROTOCOL_NSURI);

         addNameIDFormatsToMetaData(idpSsoDescriptor);

         addKeyDescriptorToMetaData(idpSsoDescriptor);

         EntityDescriptorType entityDescriptor = metaDataFactory.createEntityDescriptorType();
         entityDescriptor.setEntityID(getEntityId());
         entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(idpSsoDescriptor);

         Marshaller marshaller = metaDataJaxbContext.createMarshaller();
         marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
         marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         marshaller.marshal(metaDataFactory.createEntityDescriptor(entityDescriptor), writer);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }

   @Dialogued(join = true)
   public void authenticationSucceeded(SamlNameId nameId, List<AttributeType> attributes)
   {
      SamlPrincipal samlPrincipal = new SamlPrincipal();
      samlPrincipal.setNameId(nameId);
      if (attributes != null)
      {
         samlPrincipal.setAttributes(attributes);
      }
      else
      {
         samlPrincipal.setAttributes(new LinkedList<AttributeType>());
      }
      SamlIdpSession session = samlIdpSessions.addSession(samlPrincipal, (SamlExternalServiceProvider) samlDialogue.get().getExternalProvider());

      samlIdpSingleSignOnService.handleSucceededAuthentication(session);
   }

   public void authenticationSucceeded(SamlIdpSession sessionToJoin)
   {
      sessionToJoin.getServiceProviders().add((SamlExternalServiceProvider) samlDialogue.get().getExternalProvider());

      samlIdpSingleSignOnService.handleSucceededAuthentication(sessionToJoin);
   }

   @Dialogued(join = true)
   public void authenticationFailed()
   {
      samlIdpSingleSignOnService.handleFailedAuthentication();
   }

   public Set<SamlIdpSession> getSessions()
   {
      return samlIdpSessions.getSessions();
   }

   @Dialogued(join = true)
   public void logout(SamlPrincipal principal, List<String> indexes)
   {
      samlIdpSingleSignLogoutService.handleIDPInitiatedSingleLogout(principal, indexes);
   }

   @Override
   public SamlIdpOrSp getIdpOrSp()
   {
      return SamlIdpOrSp.IDP;
   }
}
