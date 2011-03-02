package org.jboss.seam.security.externaltest.integration.client;

import org.jboss.arquillian.spi.Context;
import org.jboss.arquillian.spi.DeployableContainer;
import org.jboss.arquillian.spi.event.container.BeforeUnDeploy;
import org.jboss.arquillian.spi.event.suite.EventHandler;

public class BeforeUnDeployEventHandler implements EventHandler<BeforeUnDeploy>
{
   public void callback(Context context, BeforeUnDeploy event) throws Exception
   {
      DeployableContainer container = context.get(DeployableContainer.class);
      container.undeploy(context, ArchiveBuilder.getArchive("idp"));
      container.undeploy(context, ArchiveBuilder.getArchive("op"));
      container.undeploy(context, ArchiveBuilder.getArchive("rp"));
   }
}
