package net.floodlightcontroller.failover;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;


public interface IFailureDiscoveryListener {
	
	public void singleLinkRemovedFailure(DatapathId slrDrc,OFPort slrSrcPort, DatapathId slrDst, OFPort slrDstPort);
}
