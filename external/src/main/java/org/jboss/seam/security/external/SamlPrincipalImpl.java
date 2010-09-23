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

import java.util.LinkedList;
import java.util.List;

import org.jboss.seam.security.external.jaxb.samlv2.assertion.AssertionType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.saml.api.SamlNameId;
import org.jboss.seam.security.external.saml.api.SamlPrincipal;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlPrincipalImpl implements SamlPrincipal
{
   private SamlNameId nameId;

   private List<AttributeType> attributes = new LinkedList<AttributeType>();

   private AssertionType assertion;

   public SamlNameId getNameId()
   {
      return nameId;
   }

   public void setNameId(SamlNameId nameId)
   {
      this.nameId = nameId;
   }

   public List<AttributeType> getAttributes()
   {
      return attributes;
   }

   public void setAttributes(List<AttributeType> attributes)
   {
      this.attributes = attributes;
   }

   public AssertionType getAssertion()
   {
      return assertion;
   }

   public void setAssertion(AssertionType assertion)
   {
      this.assertion = assertion;
   }

   @Override
   public int hashCode()
   {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((nameId == null) ? 0 : nameId.hashCode());
      return result;
   }

   @Override
   public boolean equals(Object obj)
   {
      if (this == obj)
         return true;
      if (obj == null)
         return false;
      if (getClass() != obj.getClass())
         return false;
      SamlPrincipalImpl other = (SamlPrincipalImpl) obj;
      if (nameId == null)
      {
         if (other.nameId != null)
            return false;
      }
      else if (!nameId.equals(other.nameId))
         return false;
      return true;
   }
}
