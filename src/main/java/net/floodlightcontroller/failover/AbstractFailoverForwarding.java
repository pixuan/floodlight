package net.floodlightcontroller.failover;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.MatchUtils;
import net.floodlightcontroller.util.OFMessageDamper;

public abstract class AbstractFailoverForwarding implements IOFMessageListener{
	protected static Logger log =
			LoggerFactory.getLogger(AbstractFailoverForwarding.class);
	
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	
	public static int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
	public static int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	public static int FLOWMOD_DEFAULT_PRIORITY = 1; // 0 is the default table-miss flow in OF1.3+, so we need to use 1

	
	protected IFloodlightProviderService floodlightProviderService;
	protected ITopologyService topologyService;
	protected IRoutingService routingEngineService;
	protected IOFSwitchService switchService;
	
	protected OFMessageDamper messageDamper;
	
	
	// flow-mod - for use in the cookie
	public static final int FORWARDING_APP_ID = 2; // TODO: This must be managed
	// by a global APP_ID class
	static {
		AppCookie.registerApp(FORWARDING_APP_ID, "Forwarding");
	}
	public static final U64 appCookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
	
	// Comparator for sorting by SwitchCluster
	public Comparator<SwitchPort> clusterIdComparator =
			new Comparator<SwitchPort>() {
		@Override
		public int compare(SwitchPort d1, SwitchPort d2) {
			DatapathId d1ClusterId = topologyService.getL2DomainId(d1.getSwitchDPID());
			DatapathId d2ClusterId = topologyService.getL2DomainId(d2.getSwitchDPID());
			return d1ClusterId.compareTo(d2ClusterId);
		}
	};
	
	/**
	 * All subclasses must define this function if they want any specific
	 * forwarding action
	 *
	 * @param sw
	 *            Switch that the packet came in from
	 * @param pi
	 *            The packet that came in
	 * @param decision
	 *            Any decision made by a policy engine
	 */
	public abstract Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, 
			IRoutingDecision decision, FloodlightContext cntx);
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			IRoutingDecision decision = null;
			if (cntx != null) {
				decision = RoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
			}

			return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
		default:
			break;
		}
		return Command.CONTINUE;
	}
	
	/**
	 * Push routes from back to front
	 * @param route Route to push
	 * @param match OpenFlow fields to match on
	 * @param srcSwPort Source switch port for the first hop
	 * @param dstSwPort Destination switch port for final hop
	 * @param cookie The cookie to set in each flow_mod
	 * @param cntx The floodlight context
	 * @param reqeustFlowRemovedNotifn if set to true then the switch would
	 * send a flow mod removal notification when the flow mod expires
	 * @param doFlush if set to true then the flow mod would be immediately
	 *        written to the switch
	 * @param flowModCommand flow mod. command to use, e.g. OFFlowMod.OFPFC_ADD,
	 *        OFFlowMod.OFPFC_MODIFY etc.
	 * @return srcSwitchIncluded True if the source switch is included in this route
	 */
	public boolean pushRoute(Route route, Match match, OFPacketIn pi,
			DatapathId pinSwitch, U64 cookie, FloodlightContext cntx,
			boolean reqeustFlowRemovedNotifn, boolean doFlush,
			OFFlowModCommand flowModCommand) {
		boolean srcSwitchIncluded = false;
		
		List<NodePortTuple> switchPortList = route.getPath();
		
		for(int index = switchPortList.size()-1; index>0; index-=2) {
			// indx and indx-1 will always have the same switch DPID.
			DatapathId switchDPID = switchPortList.get(index).getNodeId();
			IOFSwitch sw = switchService.getSwitch(switchDPID);
			
			if (sw == null) {
				if (log.isWarnEnabled()) {
					log.warn("Unable to push route, switch at DPID {} " + "not available", switchDPID);
				}
				return srcSwitchIncluded;
			}
			//need to build flow mod based on what type it is. Cannot set command later
			OFFlowMod.Builder fmb;
			switch(flowModCommand) {
			case ADD:
				fmb = sw.getOFFactory().buildFlowAdd();
				break;
			case DELETE:
				fmb = sw.getOFFactory().buildFlowDelete();
				break;
			case MODIFY:
				fmb = sw.getOFFactory().buildFlowModify();
				break;
			case DELETE_STRICT:
				fmb = sw.getOFFactory().buildFlowDeleteStrict();
				break;
			default:
				log.error("Could not decode OFFlowModCommand. Using MODIFY_STRICT. (Should another be used as the default?)");    
			case MODIFY_STRICT:
				fmb = sw.getOFFactory().buildFlowModifyStrict();
				break;
			}
			
			OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
			List<OFAction> actions = new ArrayList<OFAction>();
			Match.Builder mb = MatchUtils.createRetentiveBuilder(match);
			
			// set input and output ports on the switch
			OFPort outPort = switchPortList.get(index).getPortId();
			OFPort inPort = switchPortList.get(index-1).getPortId();
			mb.setExact(MatchField.IN_PORT, inPort);
			aob.setPort(outPort);
			aob.setMaxLen(Integer.MAX_VALUE);
			actions.add(aob.build());
			
			// compile
			fmb.setMatch(mb.build()) // was match w/o modifying input port
			.setActions(actions)
			.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
			.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
			.setBufferId(OFBufferId.NO_BUFFER)
			.setCookie(cookie)
			.setOutPort(outPort)
			.setPriority(FLOWMOD_DEFAULT_PRIORITY);
			
			try {
				if (log.isTraceEnabled()) {
					log.trace("Pushing Route flowmod routeIndx={} " +
							"sw={} inPort={} outPort={}",
							new Object[] {index,
							sw,
							fmb.getMatch().get(MatchField.IN_PORT),
							outPort });
				}
				messageDamper.write(sw, fmb.build());
				if(doFlush) {
					sw.flush();
				}
				
				// Push the packet out the source switch
				if(sw.getId().equals(pinSwitch)) {
					// TODO: Instead of doing a packetOut here we could also
					// send a flowMod with bufferId set....
					pushPacket(sw, pi, false, outPort, cntx);
					srcSwitchIncluded = true;
				}
			} catch (IOException e) {
				log.error("Failure writing flow mod", e);
			}
		}
		return srcSwitchIncluded;
	}
	
	/**
	 * Pushes a packet-out to a switch.  The assumption here is that
	 * the packet-in was also generated from the same switch.  Thus, if the input
	 * port of the packet-in and the outport are the same, the function will not
	 * push the packet-out.
	 * @param sw        switch that generated the packet-in, and from which packet-out is sent
	 * @param pi        packet-in
	 * @param useBufferId  if true, use the bufferId from the packet in and
	 * do not add the packetIn's payload. If false set bufferId to
	 * BUFFER_ID_NONE and use the packetIn's payload
	 * @param outport   output port
	 * @param cntx      context of the packet
	 */
	protected void pushPacket(IOFSwitch sw, OFPacketIn pi, boolean useBufferId,
			OFPort outport, FloodlightContext cntx) {
		if(pi == null)
			return;
		// The assumption here is (sw) is the switch that generated the
		// packet-in. If the input port is the same as output port, then
		// the packet-out should be ignored.
		if ((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)).equals(outport)) {
			if (log.isDebugEnabled()) {
				log.debug("Attempting to do packet-out to the same " +
						"interface as packet-in. Dropping packet. " +
						" SrcSwitch={}, pi={}",
						new Object[]{sw, pi});
				return;
			}
		}
		
		if (log.isTraceEnabled()) {
			log.trace("PacketOut srcSwitch={} pi={}",
					new Object[] {sw, pi});
		}
		
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		//set actions
		List<OFAction> actions = new ArrayList<OFAction>();
		OFAction action = sw.getOFFactory().actions().output(outport, Integer.MAX_VALUE);
		actions.add(action);
		pob.setActions(actions);
		
		if(useBufferId) {
			pob.setBufferId(pi.getBufferId());
		} else {
			pob.setBufferId(OFBufferId.NO_BUFFER);
		}
		
		if(pob.getBufferId() == OFBufferId.NO_BUFFER) {
			pob.setData(pi.getData());
		}
		
		pob.setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)));
		
		try {
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			log.error("Failure writing packet out", e);
		}
		
	}
	
	/**
	 * init data structures
	 *
	 */
	protected void init() {
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
	}
	
	/**
	 * Adds a listener for devicemanager and registers for PacketIns.
	 */
	protected void startUp() {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
	}
}
