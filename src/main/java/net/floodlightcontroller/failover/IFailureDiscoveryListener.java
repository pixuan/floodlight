package net.floodlightcontroller.failover;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;


public interface IFailureDiscoveryListener {
	
	public void singleLinkRemovedFailure(DatapathId slrSrc,OFPort slrSrcPort, DatapathId slrDst, OFPort slrDstPort);
}
