package org.jboss.seam.security.externaltest.integration.client;

import org.jboss.arquillian.spi.Context;
import org.jboss.arquillian.spi.DeployableContainer;
import org.jboss.arquillian.spi.event.container.AfterDeploy;
import org.jboss.arquillian.spi.event.suite.EventHandler;

public class AfterDeployEventHandler implements EventHandler<AfterDeploy>
{
   public void callback(Context context, AfterDeploy event) throws Exception
   {
      DeployableContainer container = context.get(DeployableContainer.class);
      container.deploy(context, ArchiveBuilder.getArchive("idp"));
      container.deploy(context, ArchiveBuilder.getArchive("op"));
      container.deploy(context, ArchiveBuilder.getArchive("rp"));
   }

}
