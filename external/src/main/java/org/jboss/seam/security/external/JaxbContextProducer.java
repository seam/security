package org.jboss.seam.security.external;

import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

/**
 * @author Marcel Kolsteren
 */
public class JaxbContextProducer {
    @Produces
    @JaxbContext(Object.class)
    public JAXBContext getContext(InjectionPoint ip) {
        JAXBContext jaxbContext;
        try {
            Class<?>[] classes = ip.getAnnotated().getAnnotation(JaxbContext.class).value();
            jaxbContext = JAXBContext.newInstance(classes);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
        return jaxbContext;
    }
}
