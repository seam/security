package org.jboss.seam.security.external.saml;

import java.io.StringWriter;
import java.util.GregorianCalendar;

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

/**
 * @author Marcel Kolsteren
 */
public class SamlUtils {

    public static XMLGregorianCalendar getXMLGregorianCalendarNow() {
        return getXMLGregorianCalendar(new GregorianCalendar());
    }

    public static XMLGregorianCalendar getXMLGregorianCalendarNowPlusDuration(int field, int amount) {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.add(field, amount);
        return getXMLGregorianCalendar(gregorianCalendar);
    }

    private static XMLGregorianCalendar getXMLGregorianCalendar(GregorianCalendar gregorianCalendar) {
        try {
            DatatypeFactory dtf = DatatypeFactory.newInstance();
            return dtf.newXMLGregorianCalendar(gregorianCalendar);
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean hasAssertionExpired(AssertionType assertion) {
        ConditionsType conditionsType = assertion.getConditions();
        if (conditionsType != null) {
            XMLGregorianCalendar now = getXMLGregorianCalendarNow();
            XMLGregorianCalendar notBefore = conditionsType.getNotBefore();
            XMLGregorianCalendar notOnOrAfter = conditionsType.getNotOnOrAfter();

            if (notBefore != null) {
                int val = notBefore.compare(now);
                if (val == DatatypeConstants.INDETERMINATE || val == DatatypeConstants.GREATER) {
                    return true;
                }
            }

            if (notOnOrAfter != null) {
                int val = notOnOrAfter.compare(now);
                if (val != DatatypeConstants.GREATER) {
                    return true;
                }
            }

            return false;
        } else {
            return false;
        }
    }

    public static String getDocumentAsString(Document document) {
        Source source = new DOMSource(document);
        StringWriter sw = new StringWriter();

        Result streamResult = new StreamResult(sw);
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            transformer.transform(source, streamResult);
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }

        return sw.toString();
    }
}
