package org.jboss.seam.security.api;

/**
 * Seam implementation of the PicketLink Group interface
 * 
 * @author Shane Bryzak
 */
public class Group implements org.picketlink.idm.api.Group
{
   private String groupType;
   private String name;
   
   public Group(String groupType, String name)
   {
      this.groupType = groupType;
      this.name = name;
   }
   
   public String getGroupType()
   {
      return groupType;
   }

   public String getName()
   {
      return name;
   }

   public String getKey()
   {
      return String.format("jbpid_group_id_._._%s_._._%s", groupType, name);
   }
}
