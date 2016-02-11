package net.floodlightcontroller.failover;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFFlowStatsRequest;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;













import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.MatchUtils;

public class RestorationForwarding extends AbstractFailoverForwarding implements
		IFloodlightModule, IFailureDiscoveryListener {
	protected static Logger log =
			LoggerFactory.getLogger(RestorationForwarding.class);
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
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		// We found a routing decision (i.e. Firewall is enabled... it's the only thing that makes RoutingDecisions)
		if (decision != null) {
			if (log.isTraceEnabled()) {
				log.trace("Forwaring decision={} was made for PacketIn={}", decision.getRoutingAction().toString(), pi);
			}

			switch(decision.getRoutingAction()) {
			case NONE:
				// don't do anything
				return Command.CONTINUE;
			case FORWARD_OR_FLOOD:
			case FORWARD:
				doForwardFlow(sw, pi, cntx, false);
				return Command.CONTINUE;
			case MULTICAST:
				// treat as broadcast
				doFlood(sw, pi, cntx);
				return Command.CONTINUE;
			case DROP:
				doDropFlow(sw, pi, decision, cntx);
				return Command.CONTINUE;
			default:
				log.error("Unexpected decision made for this packet-in={}", pi, decision.getRoutingAction());
				return Command.CONTINUE;
			}
		} else { // No routing decision was found. Forward to destination or flood if bcast or mcast.
			if (log.isTraceEnabled()) {
				log.trace("No decision was made for PacketIn={}, forwarding", pi);
			}

			if (eth.isBroadcast() || eth.isMulticast()) {
				doFlood(sw, pi, cntx);
			} else {
				doForwardFlow(sw, pi, cntx, false);
			}
		}
		
		return Command.CONTINUE;
	}
	
	protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, boolean requestFlowRemovedNotifn) {
		
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Check if we have the location of the destination
		IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);
		
		if(dstDevice != null) {
			IDevice srcDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE);
			DatapathId srcIsland = topologyService.getL2DomainId(sw.getId());
			
			if (srcDevice == null) {
				log.debug("No device entry found for source device");
				return;
			}
			if (srcIsland == null) {
				log.debug("No openflow island found for source {}/{}",
						sw.getId().toString(), inPort);
				return;
			}
			
			// Validate that we have a destination known on the same island
			// Validate that the source and destination are not on the same switchport
			boolean on_same_island = false;
			boolean on_same_if = false;
			for(SwitchPort dstDap : dstDevice.getAttachmentPoints()) {
				DatapathId dstSwDpid = dstDap.getSwitchDPID();
				DatapathId dstIsland = topologyService.getL2DomainId(dstSwDpid);
				if(dstIsland != null && dstIsland.equals(srcIsland)) {
					on_same_island = true;
					if(sw.getId().equals(dstSwDpid) && inPort.equals(dstDap.getPort())) {
						on_same_if = true;
					}
					break;
				}
			}
			
			if (!on_same_island) {
				// Flood since we don't know the dst device
				if (log.isTraceEnabled()) {
					log.trace("No first hop island found for destination " +
							"device {}, Action = flooding", dstDevice);
				}
				doFlood(sw, pi, cntx);
				return;
			}

			if (on_same_if) {
				if (log.isTraceEnabled()) {
					log.trace("Both source and destination are on the same " +
							"switch/port {}/{}, Action = NOP",
							sw.toString(), inPort);
				}
				return;
			}

			// Install all the routes where both src and dst have attachment
			// points.  Since the lists are stored in sorted order we can
			// traverse the attachment points in O(m+n) time
			SwitchPort[] srcDaps = srcDevice.getAttachmentPoints();
			Arrays.sort(srcDaps, clusterIdComparator);
			SwitchPort[] dstDaps = dstDevice.getAttachmentPoints();
			Arrays.sort(dstDaps, clusterIdComparator);
			
			int iSrcDaps = 0, iDstDaps = 0;
			while(iSrcDaps < srcDaps.length && iDstDaps < dstDaps.length) {
				SwitchPort srcDap = srcDaps[iSrcDaps];
				SwitchPort dstDap = dstDaps[iDstDaps];
				
				// srcCluster and dstCluster here cannot be null as
				// every switch will be at least in its own L2 domain.
				DatapathId srcCluster = topologyService.getL2DomainId(srcDap.getSwitchDPID());
				DatapathId dstCluster = topologyService.getL2DomainId(dstDap.getSwitchDPID());
				
				int srcVsDest = srcCluster.compareTo(dstCluster);
				if(srcVsDest == 0) {
					if (!srcDap.equals(dstDap)) {
						System.out.println("prepare to assign a flowtable to the route here!");
						//TODO From here to send the flow add message to the OpenFlow switch
						Route route = routingEngineService.getRoute(srcDap.getSwitchDPID(), srcDap.getPort(),
										dstDap.getSwitchDPID(), dstDap.getPort(), U64.of(0));
						if(route != null) {
							if (log.isTraceEnabled()) {
								log.trace("pushRoute inPort={} route={} " +
										"destination={}:{}",
										new Object[] { inPort, route,
										dstDap.getSwitchDPID(),
										dstDap.getPort()});
							}
							U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
							
							// if there is prior routing decision use route's match
							Match routeMatch = null;
							IRoutingDecision decision = null;
							if(cntx != null) {
								decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
							}
							if(decision != null) {
								routeMatch = decision.getMatch();
							} else {
								// The packet in match will only contain the port number.
								// We need to add in specifics for the hosts we're routing between.
								Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, 
										IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
								VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
								MacAddress srcMac = eth.getSourceMACAddress();
								MacAddress dstMac = eth.getDestinationMACAddress();
								
								// A retentive builder will remember all MatchFields of the parent the builder was generated from
								// With a normal builder, all parent MatchFields will be lost if any MatchFields are added, mod, del
								// TODO (This is a bug in Loxigen and the retentive builder is a workaround.)
								Match.Builder mb = sw.getOFFactory().buildMatch();
								mb.setExact(MatchField.IN_PORT, inPort)
									.setExact(MatchField.ETH_SRC, srcMac)
									.setExact(MatchField.ETH_DST, dstMac);
								
								if(!vlan.equals(VlanVid.ZERO)) {
									mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
								}
								// TODO Detect switch type and match to create hardware-implemented flow
								// TODO Set option in config file to support specific or MAC-only matches
								if(eth.getEtherType() == Ethernet.TYPE_IPv4) {
									IPv4 ip = (IPv4)eth.getPayload();
									IPv4Address srcIp = ip.getSourceAddress();
									IPv4Address dstIp = ip.getDestinationAddress();
									mb.setExact(MatchField.IPV4_SRC, srcIp)
										.setExact(MatchField.IPV4_DST, dstIp)
										.setExact(MatchField.ETH_TYPE, EthType.IPv4);
									
									if(ip.getProtocol().equals(IpProtocol.TCP)) {
										TCP tcp = (TCP)ip.getPayload();
										mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
											.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
											.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
									} else if(ip.getProtocol().equals(IpProtocol.UDP)) {
										UDP udp = (UDP)ip.getPayload();
										mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
											.setExact(MatchField.UDP_SRC, udp.getSourcePort())
											.setExact(MatchField.UDP_DST, udp.getDestinationPort());
									}
									
								} else if(eth.getEtherType() == Ethernet.TYPE_ARP) {
									mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
								}
								
								routeMatch = mb.build();

							}
							
							//TODO From here to pushRoute based on route and routeMatch;
							

							pushRoute(route, routeMatch, pi, sw.getId(), cookie,
									cntx, requestFlowRemovedNotifn, false,
									OFFlowModCommand.ADD);
							
						} else {
							log.info("No route is found between src/dst {}/{}", 
									srcDap.getSwitchDPID(), dstDap.getSwitchDPID());
						}
					}
					
					iSrcDaps++;
					iDstDaps++;
				} else if(srcVsDest < 0) {
					iSrcDaps++;
				} else {
					iDstDaps++;
				}
			}
		} else {
			// Flood since we don't know the dst device
			doFlood(sw, pi, cntx);
		}
	}
	
	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {		
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		if (topologyService.isIncomingBroadcastAllowed(sw.getId(), inPort) == false) {
			if (log.isTraceEnabled()) {
				log.trace("doFlood, drop broadcast packet, pi={}, " +
						"from a blocked port, srcSwitch=[{},{}], linkInfo={}",
						new Object[] {pi, sw.getId(), inPort});
			}
			return;
		}

		// Set Action to flood
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		if (sw.hasAttribute(IOFSwitch.PROP_SUPPORTS_OFPP_FLOOD)) {
			actions.add(sw.getOFFactory().actions().output(OFPort.FLOOD, Integer.MAX_VALUE)); // FLOOD is a more selective/efficient version of ALL
		} else {
			actions.add(sw.getOFFactory().actions().output(OFPort.ALL, Integer.MAX_VALUE));
		}
		pob.setActions(actions);

		// set buffer-id, in-port and packet-data based on packet-in
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		pob.setData(pi.getData());

		try {
			if (log.isTraceEnabled()) {
				log.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			log.error("Failure writing PacketOut switch={} packet-in={} packet-out={}",
					new Object[] {sw, pi, pob.build()}, e);
		}

		return;
	}
	
	protected void doDropFlow(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
		// initialize match structure and populate it based on the packet in's match
		Match.Builder mb = null;
		if (decision.getMatch() != null) {
			/* This routing decision should be a match object with all appropriate fields set,
			 * not just masked. If it's a decision that matches the packet we received, then simply setting
			 * the masks to the new match will create the same match in the end. We can just use the routing
			 * match object instead.
			 * 
			 * The Firewall is currently the only module/service that sets routing decisions in the context 
			 * store (or instantiates any for that matter). It's disabled by default, so as-is a decision's 
			 * match should always be null, meaning this will never be true.
			 */
			mb = decision.getMatch().createBuilder();
		} else {
			mb = pi.getMatch().createBuilder(); // otherwise no route is known so go based on packet's match object
		}

		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd(); // this will be a drop-flow; a flow that will not output to any ports
		List<OFAction> actions = new ArrayList<OFAction>(); // set no action to drop
		U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);

		fmb.setCookie(cookie)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(mb.build())
		.setActions(actions) // empty list
		.setPriority(FLOWMOD_DEFAULT_PRIORITY);

		try {
			if (log.isDebugEnabled()) {
				log.debug("write drop flow-mod sw={} match={} flow-mod={}",
						new Object[] { sw, mb.build(), fmb.build() });
			}
			boolean dampened = messageDamper.write(sw, fmb.build());
			log.debug("OFMessage dampened: {}", dampened);
		} catch (IOException e) {
			log.error("Failure writing drop flow mod", e);
		}
	}
	
	// ****************
	// IOFMessageListener
	// ****************
	
	@Override
	public String getName() {
		return RestorationForwarding.class.getSimpleName();
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
	public void singleLinkRemovedFailure(DatapathId slrSrc, OFPort slrSrcPort, DatapathId slrDst, OFPort slrDstPort) {
		IOFSwitch slrSrcSwitch = switchService.getActiveSwitch(slrSrc);
		OFFlowStatsRequest.Builder srSrcBuilder = slrSrcSwitch.getOFFactory().buildFlowStatsRequest();
		//OFStatsRequest.Builder<OFFlowStatsReply> srBuilder = slrSrcSwitch.getOFFactory().buildFlowStatsRequest();
		Match.Builder mbSrc = slrSrcSwitch.getOFFactory().buildMatch();
		//mbSrc.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		srSrcBuilder.setOutPort(slrSrcPort);
		srSrcBuilder.setMatch(mbSrc.build());

		IOFSwitch slrDstSwitch = switchService.getActiveSwitch(slrDst);
		OFFlowStatsRequest.Builder srDstBuilder = slrDstSwitch.getOFFactory().buildFlowStatsRequest();
		//OFStatsRequest.Builder<OFFlowStatsReply> srBuilder = slrSrcSwitch.getOFFactory().buildFlowStatsRequest();
		Match.Builder mbDst = slrDstSwitch.getOFFactory().buildMatch();
		srDstBuilder.setOutPort(slrDstPort);
		//mbDst.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		srDstBuilder.setMatch(mbDst.build());
		
		ExecutorService executor = Executors.newCachedThreadPool();
		SwitchFlowStatsCheckTask sfsct = new SwitchFlowStatsCheckTask(slrSrcSwitch, srSrcBuilder);
		executor.submit(sfsct);
		
		executor.shutdown();
		/*
		//源交换机的流表项
		ListeningExecutorService executorService = MoreExecutors.listeningDecorator(Executors.newCachedThreadPool());
		ListenableFuture<List<OFFlowStatsReply>> srcListenableFuture = executorService.submit(
				new Callable<List<OFFlowStatsReply>>() {
					@Override
					public List<OFFlowStatsReply> call() throws Exception {
						return slrSrcSwitch.writeStatsRequest(srSrcBuilder.build()).get(PORT_STATS_INTERVAL / 2, TimeUnit.SECONDS);
					}
				});
		Futures.addCallback(srcListenableFuture, new FutureCallback<List<OFFlowStatsReply>>() {
			@Override
			public void onSuccess(List<OFFlowStatsReply> srcFsReply) {
				System.out.println("src values: " + srcFsReply);
			}

			@Override
			public void onFailure(Throwable e) {
				log.error("Failure retrieving statistics from switch {}. {}", slrSrcSwitch, e);
			}
		});
		
		//目交换机的流表项
		ListenableFuture<List<OFFlowStatsReply>> dstListenableFuture = executorService.submit(
				new Callable<List<OFFlowStatsReply>>() {
					@Override
					public List<OFFlowStatsReply> call() throws Exception {
						return slrDstSwitch.writeStatsRequest(srDstBuilder.build()).get(PORT_STATS_INTERVAL / 2, TimeUnit.SECONDS);
					}
				});
		Futures.addCallback(dstListenableFuture, new FutureCallback<List<OFFlowStatsReply>>() {
			@Override
			public void onSuccess(List<OFFlowStatsReply> dstFsReply) {
				System.out.println("dst values: " + dstFsReply);
			}

			@Override
			public void onFailure(Throwable e) {
				log.error("Failure retrieving statistics from switch {}. {}", slrDstSwitch, e);
			}
		});
		
		executorService.shutdown();
		
		System.out.println("srcport : " + slrSrcPort);
		System.out.println("dstport : " + slrDstPort);
		
		*/
		/*
		ListenableFuture<List<OFFlowStatsReply>> lf = slrSrcSwitch.writeStatsRequest(srBuilder.build());
		List<OFFlowStatsReply> values = new ArrayList<OFFlowStatsReply>();
		try {
			values = (List<OFFlowStatsReply>)lf.get(PORT_STATS_INTERVAL / 2, TimeUnit.SECONDS);
		} catch (Exception e) {
			log.error("Failure retrieving statistics from switch {}. {}", slrSrcSwitch, e);
		} 
		System.out.println("values: " + values);
		*/
	}
	
	class SwitchFlowStatsCheckTask implements Runnable {
		IOFSwitch sw;
		OFFlowStatsRequest.Builder fsrb;
		List<OFFlowStatsReply> statsReplyList;
		
		SwitchFlowStatsCheckTask(IOFSwitch sw, OFFlowStatsRequest.Builder fsrb) {
			this.sw = sw;
			this.fsrb = fsrb;
			statsReplyList = new ArrayList<OFFlowStatsReply>();
		}
		
		@Override
		public void run() {
			ListenableFuture<List<OFFlowStatsReply>> lf = sw.writeStatsRequest(fsrb.build());
			try {
				statsReplyList = (List<OFFlowStatsReply>)lf.get(PORT_STATS_INTERVAL / 2, TimeUnit.SECONDS);
			} catch(Exception e) {
				log.error("Failure retrieving statistics from switch {}. {}", sw, e);
				return;
			}
			if(statsReplyList.isEmpty())
				return;
			OFFlowStatsReply flowStatsReply = statsReplyList.get(0);
			List<OFFlowStatsEntry> flowStatsEntryList = flowStatsReply.getEntries();
			for(OFFlowStatsEntry fsEntry : flowStatsEntryList) {
				Match match = fsEntry.getMatch();
				MacAddress eth_src = match.get(MatchField.ETH_SRC);
				MacAddress eth_dst = match.get(MatchField.ETH_DST);
				IPv4Address ipv4_src = match.get(MatchField.IPV4_SRC);
				IPv4Address ipv4_dst = match.get(MatchField.IPV4_DST);
				//IDevice srcDev = deviceService.getDevice(eth_src.getLong());
				@SuppressWarnings("unchecked")
				Iterator<Device> srcDevIter = (Iterator<Device>)deviceService.queryDevices(eth_src, null, null, null, null);
				@SuppressWarnings("unchecked")
				Iterator<Device> dstDevIter = (Iterator<Device>)deviceService.queryDevices(eth_dst, null, null, null, null);
				IDevice srcDev = null;
				IDevice dstDev = null;
				while(srcDevIter.hasNext()) 
					srcDev = srcDevIter.next();
				while(dstDevIter.hasNext()) 
					dstDev = dstDevIter.next();
				
				if(srcDev != null & dstDev != null) {
					// Install all the routes where both src and dst have attachment
					// points.  Since the lists are stored in sorted order we can
					// traverse the attachment points in O(m+n) time
					SwitchPort[] srcDaps = srcDev.getAttachmentPoints();
					Arrays.sort(srcDaps, clusterIdComparator);
					SwitchPort[] dstDaps = dstDev.getAttachmentPoints();
					Arrays.sort(dstDaps, clusterIdComparator);
					
					
					int iSrcDaps = 0, iDstDaps = 0;
					while(iSrcDaps < srcDaps.length && iDstDaps < dstDaps.length) {
						SwitchPort srcDap = srcDaps[iSrcDaps];
						SwitchPort dstDap = dstDaps[iDstDaps];
						
						IOFSwitch srcSwitch = switchService.getActiveSwitch(srcDap.getSwitchDPID());
						IOFSwitch dstSwitch = switchService.getActiveSwitch(dstDap.getSwitchDPID());
						
						// srcCluster and dstCluster here cannot be null as
						// every switch will be at least in its own L2 domain.
						DatapathId srcCluster = topologyService.getL2DomainId(srcDap.getSwitchDPID());
						DatapathId dstCluster = topologyService.getL2DomainId(dstDap.getSwitchDPID());
						
						int srcVsDest = srcCluster.compareTo(dstCluster);
						if(srcVsDest == 0) {
							if (!srcDap.equals(dstDap)) {
								//delete the old flow table
								//暂时不在删除原始流表
								
								final int currentPriority = fsEntry.getPriority();
								
								System.out.println("prepare to reassign a flowtable to the route here!");
								//TODO From here to send the flow add message to the OpenFlow switch
								Route route = routingEngineService.getRoute(srcDap.getSwitchDPID(), srcDap.getPort(),
												dstDap.getSwitchDPID(), dstDap.getPort(), U64.of(0));
								if(route != null) {
									System.out.println("the route is :" + route);
									
									U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
									
									//以下根据重新计算的路由，先删除源目对应流表项，再重新下发流表
									//首先提取原流表中的Match，另外需修改inport项为源的交换机与源主机的端口
									Match routeMatch = null;
									OFPort inport = route.getPath().get(0).getPortId();
									Match.Builder mb = srcSwitch.getOFFactory().buildMatch();
									mb.setExact(MatchField.IN_PORT, inport)
									.setExact(MatchField.ETH_SRC, eth_src)
									.setExact(MatchField.ETH_DST, eth_dst);
									
									if(match.get(MatchField.ETH_TYPE) == EthType.IPv4) {
										mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
										.setExact(MatchField.IPV4_SRC, ipv4_src)
										.setExact(MatchField.IPV4_DST, ipv4_dst);
										
										if(match.get(MatchField.IP_PROTO) == IpProtocol.TCP) {
											mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
											.setExact(MatchField.TCP_SRC, match.get(MatchField.TCP_SRC))
											.setExact(MatchField.TCP_DST, match.get(MatchField.TCP_DST));
											
										} else if (match.get(MatchField.IP_PROTO) == IpProtocol.UDP) {
											mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
											.setExact(MatchField.UDP_SRC, match.get(MatchField.UDP_SRC))
											.setExact(MatchField.UDP_DST, match.get(MatchField.UDP_DST));
										}
									} else if(match.get(MatchField.ETH_TYPE) == EthType.ARP) {
										mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
									}
									routeMatch = mb.build();
									
									System.out.println("match :" + match);
									System.out.println("route match :" + routeMatch);
									
									boolean ifpushed = pushReassignedRoute(route, routeMatch, 
											srcDap.getSwitchDPID(), cookie, currentPriority, false,
											false, OFFlowModCommand.ADD);
									System.out.println("if pushed : " + ifpushed);
								}
						
								// push reverse route 
								Route reverseRoute = routingEngineService.getRoute(dstDap.getSwitchDPID(), dstDap.getPort(),
																	srcDap.getSwitchDPID(), srcDap.getPort(), U64.of(0));
								if(reverseRoute != null) {
									System.out.println("the reverseRoute is :" + reverseRoute);
									
									U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
									
									//以下根据重新计算的路由，先删除源目对应流表项，再重新下发流表
									//首先提取原流表中的Match，另外需修改inport项为源的交换机与源主机的端口
									Match routeMatch = null;
									OFPort inport = reverseRoute.getPath().get(0).getPortId();
									Match.Builder mb = srcSwitch.getOFFactory().buildMatch();
									mb.setExact(MatchField.IN_PORT, inport)
									.setExact(MatchField.ETH_SRC, eth_dst)
									.setExact(MatchField.ETH_DST, eth_src);
									
									if(match.get(MatchField.ETH_TYPE) == EthType.IPv4) {
										mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
										.setExact(MatchField.IPV4_SRC, ipv4_dst)
										.setExact(MatchField.IPV4_DST, ipv4_src);
										
										if(match.get(MatchField.IP_PROTO) == IpProtocol.TCP) {
											mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
											.setExact(MatchField.TCP_SRC, match.get(MatchField.TCP_DST))
											.setExact(MatchField.TCP_DST, match.get(MatchField.TCP_SRC));
											
										} else if (match.get(MatchField.IP_PROTO) == IpProtocol.UDP) {
											mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
											.setExact(MatchField.UDP_SRC, match.get(MatchField.UDP_DST))
											.setExact(MatchField.UDP_DST, match.get(MatchField.UDP_SRC));
										}
									} else if(match.get(MatchField.ETH_TYPE) == EthType.ARP) {
										mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
									}
									routeMatch = mb.build();
									
									System.out.println("match :" + match);
									System.out.println("reverse route match :" + routeMatch);
									
									boolean ifpushedReverseRoute = pushReassignedRoute(reverseRoute, routeMatch, 
											dstDap.getSwitchDPID(), cookie, currentPriority, false,
											false, OFFlowModCommand.ADD);
									System.out.println("if pushed reverseRoute : " + ifpushedReverseRoute);
								}
							}
							iSrcDaps++;
							iDstDaps++;
						} else if(srcVsDest < 0) {
							iSrcDaps++;
						} else {
							iDstDaps++;
						}
					}
				} else {
					log.error("the srcDevice or dstDevice of flowstats entry {} is null", fsEntry);
				}
			}
			System.out.println("flow table: " + statsReplyList);
			
		}
		
		public boolean pushReassignedRoute(Route route, Match match, 
				DatapathId pinSwitch, U64 cookie,int currentPriority,boolean reqeustFlowRemovedNotifn,
				boolean doFlush, OFFlowModCommand flowModCommand) {
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
				//!!!!!!!
				//提升优先级为当前优先级值加1，使原有的流表项失效，可是流量直接跑到新链路上去
				//也可以先删除原有的流表项，优点是节约流表项，缺点是需要额外下发删除流表项消息
				//!!!!!!!
				fmb.setMatch(mb.build()) // was match w/o modifying input port
				.setActions(actions)
				.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
				.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
				.setBufferId(OFBufferId.NO_BUFFER)
				.setCookie(cookie)
				.setOutPort(outPort)
				.setPriority(currentPriority + 1);
				
				try {
					if (log.isTraceEnabled()) {
						log.trace("Pushing Route flowmod routeIndx={} " +
								"sw={} inPort={} outPort={}",
								new Object[] {index,
								sw,
								fmb.getMatch().get(MatchField.IN_PORT),
								outPort });
					}
					boolean writed = messageDamper.write(sw, fmb.build());
					System.out.println("writed : " + writed);
					if(doFlush) {
						sw.flush();
					}
					
					// Push the packet out the source switch
					if(sw.getId().equals(pinSwitch)) {
						// TODO: Instead of doing a packetOut here we could also
						// send a flowMod with bufferId set....
						//pushPacket(sw, pi, false, outPort, cntx);
						srcSwitchIncluded = true;
					}
				} catch (IOException e) {
					log.error("Failure writing flow mod", e);
				}
			}
			return srcSwitchIncluded;
		}
	}
}
