package org.jboss.seam.security.external.openid;

import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.security.external.EntityBean;
import org.jboss.seam.security.external.JaxbContext;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.xrds.LocalID;
import org.jboss.seam.security.external.jaxb.xrds.ObjectFactory;
import org.jboss.seam.security.external.jaxb.xrds.Service;
import org.jboss.seam.security.external.jaxb.xrds.Type;
import org.jboss.seam.security.external.jaxb.xrds.URIPriorityAppendPattern;
import org.jboss.seam.security.external.jaxb.xrds.XRD;
import org.jboss.seam.security.external.jaxb.xrds.XRDS;
import org.jboss.seam.security.external.spi.OpenIdProviderSpi;
import org.openid4java.discovery.DiscoveryInformation;

/**
 * @author Marcel Kolsteren
 */
@Typed(OpenIdProviderBean.class)
public class OpenIdProviderBean extends EntityBean implements OpenIdProviderBeanApi {
    @Inject
    private Instance<OpenIdProviderRequest> openIdProviderRequest;

    @Inject
    private OpenIdProviderAuthenticationService openIdSingleLoginSender;

    @Inject
    private ServletContext servletContext;

    @Inject
    private Instance<OpenIdProviderSpi> openIdProviderSpi;

    @Inject
    @JaxbContext(ObjectFactory.class)
    private JAXBContext jaxbContext;

    @Inject
    private ResponseHandler responseHandler;

    public String getServiceURL(OpenIdService service) {
        String path = servletContext.getContextPath() + "/openid/OP/" + service.getName();
        return createURL(path);
    }

    public String getRealm() {
        return createURL("");
    }

    public String getXrdsURL() {
        return getServiceURL(OpenIdService.XRDS_SERVICE);
    }

    /**
     * Write XRDS with OP identifier (see OpenId 2.0 Authentication spec, section
     * 7.3.2.1.1.)
     *
     * @param writer writer to use
     */
    public void writeOpIdentifierXrds(Writer writer) {
        try {
            ObjectFactory objectFactory = new ObjectFactory();

            XRDS xrds = objectFactory.createXRDS();

            XRD xrd = objectFactory.createXRD();

            Type type = objectFactory.createType();
            type.setValue(DiscoveryInformation.OPENID2_OP);
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

    public void writeClaimedIdentifierXrds(Writer writer, String opLocalIdentifier) {
        try {
            ObjectFactory objectFactory = new ObjectFactory();

            XRDS xrds = objectFactory.createXRDS();

            XRD xrd = objectFactory.createXRD();

            Type type = objectFactory.createType();
            type.setValue(DiscoveryInformation.OPENID2);
            URIPriorityAppendPattern uri = objectFactory.createURIPriorityAppendPattern();
            uri.setValue(getServiceURL(OpenIdService.OPEN_ID_SERVICE));

            Service service = objectFactory.createService();
            service.getType().add(type);
            service.getURI().add(uri);

            LocalID localId = new LocalID();
            localId.setValue(opLocalIdentifier);
            service.getLocalID().add(localId);

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

    public String getOpLocalIdentifierForUserName(String userName) {
        try {
            return createURL(getUsersPath() + URLEncoder.encode(userName, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public String getUserNameFromOpLocalIdentifier(String opLocalIdentifier) {
        String prefix = createURL(getUsersPath());
        if (opLocalIdentifier.startsWith(prefix)) {
            String urlEncodedUserName = opLocalIdentifier.replace(prefix, "");
            try {
                return URLDecoder.decode(urlEncodedUserName, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        } else {
            return null;
        }
    }

    public String getUsersPath() {
        return servletContext.getContextPath() + "/users/";
    }

    public String getUsersUrlPrefix() {
        return createURL(getUsersPath());
    }

    @Dialogued(join = true)
    public void authenticationFailed(HttpServletResponse response) {
        openIdSingleLoginSender.sendAuthenticationResponse(false, null, response);
    }

    @Dialogued(join = true)
    public void authenticationSucceeded(String userName, HttpServletResponse response) {
        openIdProviderRequest.get().setUserName(userName);
        if (openIdProviderRequest.get().getRequestedAttributes() == null) {
            openIdSingleLoginSender.sendAuthenticationResponse(true, null, response);
        } else {
            openIdProviderSpi.get().fetchParameters(openIdProviderRequest.get().getRequestedAttributes(), responseHandler.createResponseHolder(response));
        }
    }

    @Dialogued(join = true)
    public void setAttributes(Map<String, List<String>> attributeValues, HttpServletResponse response) {
        openIdSingleLoginSender.sendAuthenticationResponse(true, attributeValues, response);
    }
}
