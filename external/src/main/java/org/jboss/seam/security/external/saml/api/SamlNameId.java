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

/**
 * Name identifying a subject (person) that has been authenticated using SAML.
 * For details, refer to section 2.2 of the document 'Assertions and Protocols
 * for the OASIS 3 Security Assertion Markup Language (SAML) V2.0' .
 * 
 * @author Marcel Kolsteren
 */
public interface SamlNameId
{
   /**
    * The actual name
    * 
    * @return the name (not null)
    */
   String getValue();

   /**
    * A URI reference representing the classification of string-based identifier
    * information.
    * 
    * @return an URI reference, or null if the format is unspecified
    */
   String getFormat();

   /**
    * The security or administrative domain that qualifies the identifier. This
    * attribute provides a means to federate identifiers from disparate user
    * stores without collision.
    * 
    * @return the qualifier, or null if the name is unqualified
    */
   String getQualifier();
}
