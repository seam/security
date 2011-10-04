package org.jboss.seam.security.external.virtualapplications;

import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;

import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationCreation;
import org.jboss.solder.servlet.event.Destroyed;
import org.jboss.solder.servlet.event.Initialized;

/**
 * @author Marcel Kolsteren
 */
@ApplicationScoped
public class VirtualApplicationManager {
    @Inject
    private VirtualApplicationContextExtension virtualApplicationContextExtension;

    @Inject
    private Instance<VirtualApplicationBean> virtualApplication;

    @Inject
    private BeanManager beanManager;

    private Set<String> hostNames = new HashSet<String>();

    protected void servletInitialized(@Observes @Initialized final ServletContext context) {
        getVirtualApplicationContext().initialize(context);

        AfterVirtualApplicationManagerCreationEvent afterVirtualApplicationManagerCreation = new AfterVirtualApplicationManagerCreationEvent();
        beanManager.fireEvent(afterVirtualApplicationManagerCreation);

        for (String hostName : afterVirtualApplicationManagerCreation.getHostNames()) {
            hostNames.add(hostName);
            getVirtualApplicationContext().create(hostName);
            virtualApplication.get().setHostName(hostName);
            beanManager.fireEvent(new AfterVirtualApplicationCreation());
            getVirtualApplicationContext().detach();
        }
    }

    protected void servletDestroyed(@Observes @Destroyed final ServletContext context) {
        for (String hostName : hostNames) {
            if (getVirtualApplicationContext().isExistingVirtualApplication(hostName)) {
                attach(hostName);
                getVirtualApplicationContext().destroy();
            }
        }
    }

    protected void requestInitialized(@Observes @Initialized final ServletRequest request) {
        String hostName = request.getServerName();
        if (getVirtualApplicationContext().isExistingVirtualApplication(hostName)) {
            attach(hostName);
        }
    }

    protected void requestDestroyed(@Observes @Destroyed final ServletRequest request) {
        if (getVirtualApplicationContext().isActive()) {
            detach();
        }
    }

    public void attach(String hostName) {
        getVirtualApplicationContext().attach(hostName);
        virtualApplication.get().setHostName(hostName);
    }

    public void detach() {
        getVirtualApplicationContext().detach();
    }

    public Set<String> getHostNames() {
        return hostNames;
    }

    private VirtualApplicationContext getVirtualApplicationContext() {
        return virtualApplicationContextExtension.getVirtualApplicationContext();
    }
}
