package org.jboss.seam.security.external.openid;

import java.io.Writer;
import java.util.List;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external.EntityBean;
import org.jboss.seam.security.external.JaxbContext;
import org.jboss.seam.security.external.OpenIdRequestedAttributeImpl;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.xrds.ObjectFactory;
import org.jboss.seam.security.external.jaxb.xrds.Service;
import org.jboss.seam.security.external.jaxb.xrds.Type;
import org.jboss.seam.security.external.jaxb.xrds.URIPriorityAppendPattern;
import org.jboss.seam.security.external.jaxb.xrds.XRD;
import org.jboss.seam.security.external.jaxb.xrds.XRDS;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.openid4java.discovery.DiscoveryInformation;

/**
 * @author Marcel Kolsteren
 */
@Typed(OpenIdRpBean.class)
public class OpenIdRpBean extends EntityBean implements OpenIdRpBeanApi {
    @Inject
    private OpenIdRpAuthenticationService openIdSingleLoginSender;

    @Inject
    private ServletContext servletContext;      
    
    private String returnToPath;
    
    @Inject public void init(OpenIdConfiguration config) {
        setHostName(config.getHostName());
        setPort(config.getPort());
        setProtocol(config.getProtocol());
        setReturnToPath(config.getReturnToPath());
    }
    
    
    public String getReturnToPath() {
        return returnToPath;
    }
    
    public void setReturnToPath(String value) {
        this.returnToPath = value;
    }

    @Inject
    @JaxbContext(ObjectFactory.class)
    private JAXBContext jaxbContext;

    @Dialogued(join = true)
    public void login(String identifier, List<OpenIdRequestedAttribute> attributes, HttpServletResponse response) {
        openIdSingleLoginSender.sendAuthRequest(identifier, attributes, response);
    }

    public String getServiceURL(OpenIdService service) {
        String path = servletContext.getContextPath() + (returnToPath != null ? returnToPath : "/openid/RP/" + service.getName());
        return createURL(path);
    }

    public String getRealm() {
        return createURL("");
    }

    public String getXrdsURL() {
        return getServiceURL(OpenIdService.XRDS_SERVICE);
    }

    public void writeRpXrds(Writer writer) {
        try {
            ObjectFactory objectFactory = new ObjectFactory();

            XRDS xrds = objectFactory.createXRDS();

            XRD xrd = objectFactory.createXRD();

            Type type = objectFactory.createType();
            type.setValue(DiscoveryInformation.OPENID2_RP);
            URIPriorityAppendPattern uri = objectFactory.createURIPriorityAppendPattern();
            uri.setValue(getServiceURL(OpenIdService.OPEN_ID_SERVICE));

            Service service = objectFactory.createService();
            service.getType().add(type);
            service.getURI().add(uri);

            xrd.getService().add(service);

            xrds.getOtherelement().add(xrd);

            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            marshaller.marshal(xrds, writer);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public OpenIdRequestedAttribute createOpenIdRequestedAttribute(String alias, String typeUri, boolean required, Integer count) {
        return new OpenIdRequestedAttributeImpl(alias, typeUri, required, count);
    }
}
