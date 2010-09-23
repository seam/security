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
package org.jboss.seam.security.examples.openid;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.enterprise.inject.Model;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;
import org.jboss.seam.security.external.openid.api.OpenIdProviderApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

@Model
@DialogueScoped
public class Attributes implements Serializable
{
   private static final long serialVersionUID = -6945192710223411921L;

   private List<AttributeVO> attributeVOs;

   @Inject
   private OpenIdProviderApi providerApi;

   @Inject
   private ExternalContext externalContext;

   public void setRequestedAttributes(List<OpenIdRequestedAttribute> requestedAttributes)
   {
      attributeVOs = new LinkedList<AttributeVO>();

      for (OpenIdRequestedAttribute requestedAttribute : requestedAttributes)
      {
         AttributeVO attributeVO = new AttributeVO();
         attributeVO.setRequestedAttribute(requestedAttribute);
         attributeVOs.add(attributeVO);
      }
   }

   public List<AttributeVO> getAttributeVOs()
   {
      return attributeVOs;
   }

   public void confirm()
   {
      Map<String, List<String>> attributeValues = new HashMap<String, List<String>>();
      for (AttributeVO attributeVO : attributeVOs)
      {
         if (attributeVO.getAttributeValue() != null)
         {
            attributeValues.put(attributeVO.getRequestedAttribute().getAlias(), Arrays.asList(attributeVO.getAttributeValue()));
         }
      }
      providerApi.setAttributes(attributeValues, (HttpServletResponse) externalContext.getResponse());
   }
}
