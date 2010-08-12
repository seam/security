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

import java.io.IOException;
import java.io.StringWriter;
import java.util.GregorianCalendar;

import javax.servlet.http.HttpServletResponse;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.jboss.seam.security.external.jaxb.samlv2.assertion.AssertionType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.ConditionsType;
import org.w3c.dom.Document;

public class SamlUtils
{

   public static XMLGregorianCalendar getXMLGregorianCalendar()
   {
      try
      {
         DatatypeFactory dtf = DatatypeFactory.newInstance();
         return dtf.newXMLGregorianCalendar(new GregorianCalendar());
      }
      catch (DatatypeConfigurationException e)
      {
         throw new RuntimeException(e);
      }
   }

   public static boolean hasAssertionExpired(AssertionType assertion)
   {
      ConditionsType conditionsType = assertion.getConditions();
      if (conditionsType != null)
      {
         XMLGregorianCalendar now = getXMLGregorianCalendar();
         XMLGregorianCalendar notBefore = conditionsType.getNotBefore();
         XMLGregorianCalendar notOnOrAfter = conditionsType.getNotOnOrAfter();

         int val = notBefore.compare(now);
         if (val == DatatypeConstants.INDETERMINATE || val == DatatypeConstants.GREATER)
         {
            return true;
         }

         val = notOnOrAfter.compare(now);
         if (val != DatatypeConstants.GREATER)
         {
            return true;
         }

         return false;
      }
      else
      {
         return false;
      }
   }

   public static String getDocumentAsString(Document document)
   {
      Source source = new DOMSource(document);
      StringWriter sw = new StringWriter();

      Result streamResult = new StreamResult(sw);
      try
      {
         Transformer transformer = TransformerFactory.newInstance().newTransformer();
         transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
         transformer.setOutputProperty(OutputKeys.INDENT, "no");
         transformer.transform(source, streamResult);
      }
      catch (TransformerException e)
      {
         throw new RuntimeException(e);
      }

      return sw.toString();
   }

   public static void sendRedirect(String destination, HttpServletResponse response)
   {
      response.setCharacterEncoding("UTF-8");
      response.setHeader("Location", destination);
      response.setHeader("Pragma", "no-cache");
      response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate,private");
      response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
      try
      {
         response.sendRedirect(destination);
      }
      catch (IOException e)
      {
         throw new RuntimeException();
      }
   }
}
