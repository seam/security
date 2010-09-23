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
package org.jboss.seam.security.external.saml.api;

import java.io.Reader;
import java.util.List;

import org.jboss.seam.security.external.api.EntityConfigurationApi;
import org.jboss.seam.security.external.saml.SamlExternalEntity;

/**
 * API for the configuration of a SAML entity (i.e. a SAML Identity Provider or
 * SAML Service Provider)
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface SamlEntityConfigurationApi extends EntityConfigurationApi
{
   /**
    * The unique identification of this SAML Entity. Typically, this is
    * "https://www.your-domain.com".
    * 
    * @return the entity ID
    */
   String getEntityId();

   /**
    * {@See #getEntityId()}
    * 
    * @param entityId
    */
   void setEntityId(String entityId);

   /**
    * The preferred SAML protocol binding. By default, it is
    * {@link SamlBinding#HTTP_Post}
    * 
    * @return the preferred binding
    */
   SamlBinding getPreferredBinding();

   /**
    * See {@link #getPreferredBinding()}
    * 
    * @param preferredBinding
    */
   void setPreferredBinding(SamlBinding preferredBinding);

   /**
    * Sets the key that is used to sign outgoing messages. Remark that in
    * production deployments, the key store and the passwords giving access to
    * it need to be well secured.
    * 
    * @param keyStoreUrl URL of the key store, which must have Java Key Store
    *           (JKS) format; if it starts with "classpath://", the keystore
    *           will be read from the given location within the classpath
    * @param keyStorePass the password giving access to the key store
    * @param signingKeyAlias the alias under which the private key is stored
    *           that needs to be used for signing; the private key must be
    *           either a DSA or an RSA key
    * @param signingKeyPass the password that gives access to the private key
    */
   void setSigningKey(String keyStoreUrl, String keyStorePass, String signingKeyAlias, String signingKeyPass);

   /**
    * This method can be used to add an external SAML entity that is trusted by
    * the entity that is being configured. If the entity that is being
    * configured is an identity provider, this method can be used for adding
    * trusted service providers, and vice versa. The reader must contain a UTF-8
    * encoded XML-file with the meta information of the entity that needs to be
    * added. When this method returns, the configured entity trusts the added
    * entity (has been added to the "circle of trust"). Remark that the meta
    * data of the configured entity also needs to be loaded in the external
    * entity. How this is done is out of scope for this API, but the needed meta
    * information is served at the URL provided by {@link #getMetaDataURL}.
    * 
    * @param reader reader that reads the meta information of the entry that
    *           needs to be added
    * @return the contents of the external entity (extracted from the meta
    *         information)
    */
   SamlExternalEntity addExternalSamlEntity(Reader reader);

   /**
    * Gets the detailed of a trusted external entity, that has been added
    * previously by calling {@link #addExternalSamlEntity}.
    * 
    * @param entityId the id of the entity
    * @return an object containing the properties of the entity
    */
   SamlExternalEntity getExternalSamlEntityByEntityId(String entityId);

   /**
    * Gets a list of all external entities that have been added previously by
    * calling {@link #addExternalSamlEntity}.
    * 
    * @return the list
    */
   List<SamlExternalEntity> getExternalSamlEntities();

   /**
    * Gets the URL where the meta data of this entity is served. Call this
    * function only after configuration is complete (after you called other
    * methods on this API that change the configuration).
    * 
    * @return the URL
    */
   String getMetaDataURL();
}
