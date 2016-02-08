package net.floodlightcontroller.failover;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.topology.ITopologyService;

public class FastFailureRestorationForwarding extends AbstractFailoverForwarding implements
		IFloodlightModule, IFailureDiscoveryListener {	
	
	protected static Logger log =
			LoggerFactory.getLogger(FastFailureRestorationForwarding.class);
	protected static int PORT_STATS_INTERVAL = 10;
	
	// failure discovery
	protected IFailureDiscoveryService failureDiscoveryService;
	
	// ****************
	// AbstractFailoverForwarding
	// ****************
	
	@Override
	public net.floodlightcontroller.core.IListener.Command processPacketInMessage(
			IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision,
			FloodlightContext cntx) {
		System.out.println("There are messages!");
		return null;
	}

	// ****************
	// IOFMessageListener
	// ****************
	
	@Override
	public String getName() {
		return FastFailureRestorationForwarding.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	// ****************
	// IFloodlightModule
	// ****************
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// We don't export any services
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// We don't have any services
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(ITopologyService.class);
		l.add(IFailureDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.init();
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		this.routingEngineService = context.getServiceImpl(IRoutingService.class);
		this.switchService = context.getServiceImpl(IOFSwitchService.class);
		this.deviceService = context.getServiceImpl(IDeviceService.class);
		this.failureDiscoveryService = context.getServiceImpl(IFailureDiscoveryService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		super.startUp();
		failureDiscoveryService.addListener(this);
	}

	
	// ****************
	// IFailureDiscoveryListener
	// ****************
	
	@Override
	public void singleLinkRemovedFailure(DatapathId slrDrc, OFPort slrSrcPort,
			DatapathId slrDst, OFPort slrDstPort) {
		System.out.println("single link failure!");
	}
	
}
