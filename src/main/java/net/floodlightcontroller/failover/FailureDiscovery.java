package net.floodlightcontroller.failover;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LDUpdate;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;

public class FailureDiscovery implements IOFMessageListener, IFloodlightModule, ITopologyListener{

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected ITopologyService topologyService;
	
	//********************
	// IFloodlightModule
	//********************
	
	@Override
	public String getName() {
		return FailureDiscovery.class.getSimpleName();
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

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	            new ArrayList<Class<? extends IFloodlightService>>();
	        l.add(IFloodlightProviderService.class);
	        return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		macAddresses = new ConcurrentSkipListSet<Long>();
		logger = LoggerFactory.getLogger(FailureDiscovery.class);
		topologyService = context.getServiceImpl(ITopologyService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.FLOW_MOD, this);
		topologyService.addListener(this);

	}

	//********************
	// IOFMessageListener
	//********************
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			return this.handlePacketIn(sw.getId(), (OFPacketIn) msg,
					cntx);
		case FLOW_MOD:
			return this.handleFlowMod(sw.getId(), (OFFlowMod) msg,cntx);
		default:
			break;
		}
		return Command.CONTINUE;
	}

	private net.floodlightcontroller.core.IListener.Command handleFlowMod(
			DatapathId id, OFFlowMod msg, FloodlightContext cntx) {
		System.out.println("**********flow mod***********");
		System.out.println("id:" + id + "msg:" + msg.getActions());
		System.out.println("**********flow mod***********");
		return Command.CONTINUE;
	}

	private net.floodlightcontroller.core.IListener.Command handlePacketIn(
			DatapathId id, OFPacketIn msg, FloodlightContext cntx) {
		System.out.println("**********packet in***********");
		System.out.println("id:" + id + "msg:" + msg.getVersion());
		System.out.println("**********packet in***********");
		return Command.CONTINUE;
	}

	//********************
	// ITopologyListener
	//********************
	
	@Override
	public void topologyChanged(List<LDUpdate> linkUpdates) {
		System.out.println("**********topology have changed!***********");
		for(LDUpdate ldu : linkUpdates) {
			if(ldu.getOperation().equals(ILinkDiscovery.UpdateOperation.LINK_REMOVED)) {
				System.out.println("**********link have been removed!***********");
				System.out.println("source dpid " + ldu.getSrc());
				System.out.println("destination dpid " + ldu.getDst());
			} else if(ldu.getOperation().equals(ILinkDiscovery.UpdateOperation.LINK_UPDATED)) {
				System.out.println("**********link have been updated!***********");
				System.out.println("source dpid " + ldu.getSrc());
				System.out.println("destination dpid " + ldu.getDst());
			}
		}
	}

}
