package net.floodlightcontroller.failover;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LDUpdate;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;

public class FailureDiscovery implements IFloodlightModule, ITopologyListener, IFailureDiscoveryService {

	protected static Logger logger;
	protected ITopologyService topologyService;
	
	
	protected ArrayList<IFailureDiscoveryListener> failureDiscoveryListeners;
	
	//********************
	// IFloodlightModule
	//********************
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFailureDiscoveryService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m =
				new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		// We are the class that implements the service
		m.put(IFailureDiscoveryService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	            new ArrayList<Class<? extends IFloodlightService>>();
	        l.add(ITopologyService.class);
	        return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		logger = LoggerFactory.getLogger(FailureDiscovery.class);
		topologyService = context.getServiceImpl(ITopologyService.class);
		
		
		// We create this here because there is no ordering guarantee
		failureDiscoveryListeners = new ArrayList<IFailureDiscoveryListener>();

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		topologyService.addListener(this);

	}


	//********************
	// ITopologyListener
	//********************
	
	@Override
	public void topologyChanged(List<LDUpdate> linkUpdates) {
		/*
		System.out.println("**********topology have changed!***********");
		System.out.println("size : " + linkUpdates.size());
		System.out.println("linkUpdates " + linkUpdates);
		*/
		
		int linkRemovedCount = 0;
		DatapathId singlelinkRemovedSrc = null;
		DatapathId singlelinkRemovedDst = null;
		OFPort singlelinkRemovedSrcPort = null;
		OFPort singlelinkRemovedDstPort = null;
		
		for(LDUpdate ldu : linkUpdates) {
			if(ldu.getOperation().equals(ILinkDiscovery.UpdateOperation.LINK_REMOVED)) {
				if(linkRemovedCount == 0) {
					singlelinkRemovedSrc = ldu.getSrc();
					singlelinkRemovedDst = ldu.getDst();
					singlelinkRemovedSrcPort = ldu.getSrcPort();
					singlelinkRemovedDstPort = ldu.getDstPort();
				}
				linkRemovedCount++;
			} else if(ldu.getOperation().equals(ILinkDiscovery.UpdateOperation.LINK_UPDATED)) {
				/*
				System.out.println("**********link have been updated!***********");
				System.out.println("source dpid " + ldu.getSrc());
				System.out.println("destination dpid " + ldu.getDst());
				*/
			}
		}
		
		if(linkRemovedCount == 2) {
			for(IFailureDiscoveryListener fdl : failureDiscoveryListeners) {
				fdl.singleLinkRemovedFailure(singlelinkRemovedSrc, singlelinkRemovedSrcPort, singlelinkRemovedDst, singlelinkRemovedDstPort);
			}
		} else {
			//System.out.println("others situation!");
		}
	}

	//********************
	// IFailureDiscoveryService
	//********************
	
	@Override
	public void addListener(IFailureDiscoveryListener listener) {
		failureDiscoveryListeners.add(listener);
	}

}
