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
package org.jboss.seam.security.external.api;

/**
 * API for configuration of entities that play a role in distributed security
 * (examples of entities are SAML identity providers, SAML service providers,
 * OpenID relying parties and OpenID providers)
 * 
 * @author Marcel Kolsteren
 * 
 */
public interface EntityConfigurationApi
{
   /**
    * This property contains the protocol that is used by the entity. Either
    * "http" or "https".
    * 
    * @return the protocol
    */
   String getProtocol();

   /**
    * See {@link #getProtocol}
    * 
    * @param protocol protocol
    */
   void setProtocol(String protocol);

   /**
    * The host name which is used to access this application from a web browser
    * (by the end user).
    * 
    * @return the host name
    */
   String getHostName();

   /**
    * See {@link #getHostName}
    * 
    * @param hostName host name
    */
   void setHostName(String hostName);

   /**
    * The port at which this application is reachable from the browser of the
    * end user. This might be another port then the port where the web container
    * is listening to (in case of port forwarding). In most practical production
    * employments, this port will be the standard HTTPS port, being 443.
    * 
    * @return
    */
   int getPort();

   /**
    * See {@link #getPort}
    * 
    * @param port port
    */
   void setPort(int port);
}
