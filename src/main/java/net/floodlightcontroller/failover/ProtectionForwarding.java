package net.floodlightcontroller.failover;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFBucket;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFGroupAdd;
import org.projectfloodlight.openflow.protocol.OFGroupType;
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
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.annotations.LogMessageDoc;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.MatchUtils;

public class ProtectionForwarding extends AbstractFailoverForwarding implements
		IFloodlightModule, IFailureDiscoveryListener {	
	
	protected static Logger log =
			LoggerFactory.getLogger(ProtectionForwarding.class);
	protected static int PORT_STATS_INTERVAL = 10;
	
	protected static int GROUP_NUM = 1;
	public static int PROTECTION_FOWARDING_FLOWMOD_DEFAULT_IDLE_TIMEOUT = 0; // in seconds
	public static int PROTECTION_FORWARDING_FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	// failure discovery
	protected IFailureDiscoveryService failureDiscoveryService;
	
	// ****************
	// AbstractFailoverForwarding
	// ****************
	
	@Override
	public net.floodlightcontroller.core.IListener.Command processPacketInMessage(
			IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision,
			FloodlightContext cntx) {
		//System.out.println("There are messages!");
		
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

		if (dstDevice != null) {
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
			for (SwitchPort dstDap : dstDevice.getAttachmentPoints()) {
				DatapathId dstSwDpid = dstDap.getSwitchDPID();
				DatapathId dstIsland = topologyService.getL2DomainId(dstSwDpid);
				if ((dstIsland != null) && dstIsland.equals(srcIsland)) {
					on_same_island = true;
					if (sw.getId().equals(dstSwDpid) && inPort.equals(dstDap.getPort())) {
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

			while ((iSrcDaps < srcDaps.length) && (iDstDaps < dstDaps.length)) {
				SwitchPort srcDap = srcDaps[iSrcDaps];
				SwitchPort dstDap = dstDaps[iDstDaps];

				// srcCluster and dstCluster here cannot be null as
				// every switch will be at least in its own L2 domain.
				DatapathId srcCluster = topologyService.getL2DomainId(srcDap.getSwitchDPID());
				DatapathId dstCluster = topologyService.getL2DomainId(dstDap.getSwitchDPID());

				int srcVsDest = srcCluster.compareTo(dstCluster);
				if (srcVsDest == 0) {
					if (!srcDap.equals(dstDap)) {
						//从这里开始，进行流表下发策略的业务逻辑
						List<Route> tCDRouteList =
								routingEngineService.getTwoCompletelyDetachedRoute(srcDap.getSwitchDPID(), 
										srcDap.getPort(),
										dstDap.getSwitchDPID(),
										dstDap.getPort(), U64.of(0)); //cookie = 0, i.e., default route
						
						if(tCDRouteList == null) {
							return;
						}
						else if (tCDRouteList.size() == 1) { 
							//System.out.println("tCDRouteList : \n" + tCDRouteList);
							
							//As there isn't redundant route, just push flow table to switches
							Route route = tCDRouteList.get(0);
							if (route != null) {
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
								if (cntx != null) {
									decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
								}
								if (decision != null) {
									routeMatch = decision.getMatch();
								} else {
									// The packet in match will only contain the port number.
									// We need to add in specifics for the hosts we're routing between.
									Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
									VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
									MacAddress srcMac = eth.getSourceMACAddress();
									MacAddress dstMac = eth.getDestinationMACAddress();
									
									// A retentive builder will remember all MatchFields of the parent the builder was generated from
									// With a normal builder, all parent MatchFields will be lost if any MatchFields are added, mod, del
									// To do : (This is a bug in Loxigen and the retentive builder is a workaround.)
									Match.Builder mb = sw.getOFFactory().buildMatch();
									mb.setExact(MatchField.IN_PORT, inPort)
									.setExact(MatchField.ETH_SRC, srcMac)
									.setExact(MatchField.ETH_DST, dstMac);
									
									if (!vlan.equals(VlanVid.ZERO)) {
										mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
									}
									
									// To do : Detect switch type and match to create hardware-implemented flow
									// To do : Set option in config file to support specific or MAC-only matches
									if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
										IPv4 ip = (IPv4) eth.getPayload();
										IPv4Address srcIp = ip.getSourceAddress();
										IPv4Address dstIp = ip.getDestinationAddress();
										mb.setExact(MatchField.IPV4_SRC, srcIp)
										.setExact(MatchField.IPV4_DST, dstIp)
										.setExact(MatchField.ETH_TYPE, EthType.IPv4);
										
										if (ip.getProtocol().equals(IpProtocol.TCP)) {
											TCP tcp = (TCP) ip.getPayload();
											mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
											.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
											.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
										} else if (ip.getProtocol().equals(IpProtocol.UDP)) {
											UDP udp = (UDP) ip.getPayload();
											mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
											.setExact(MatchField.UDP_SRC, udp.getSourcePort())
											.setExact(MatchField.UDP_DST, udp.getDestinationPort());
										}	
									} else if (eth.getEtherType() == Ethernet.TYPE_ARP) {
										mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
									} 
									
									routeMatch = mb.build();
								}

								pushRoute(route, routeMatch, pi, sw.getId(), cookie,
										cntx, requestFlowRemovedNotifn, false,
										OFFlowModCommand.ADD);
							}
							
						} else if(tCDRouteList.size() == 2) {
							//System.out.println("tCDRouteList : \n" + tCDRouteList);
							
							Route firstRoute = tCDRouteList.get(0);
							Route secondRoute = tCDRouteList.get(1);
							
							if(firstRoute!=null && secondRoute!=null) {
								//System.out.println("first route is : " + firstRoute);
								//System.out.println("second route is : " + secondRoute);
								
								U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
								/* From here to build match */
								
								Match routeMatch = null;
								Match reverseRouteMatch = null;
								// The packet in match will only contain the port number.
								// We need to add in specifics for the hosts we're routing between.
								Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
								VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
								MacAddress srcMac = eth.getSourceMACAddress();
								MacAddress dstMac = eth.getDestinationMACAddress();
								
								// A retentive builder will remember all MatchFields of the parent the builder was generated from
								// With a normal builder, all parent MatchFields will be lost if any MatchFields are added, mod, del
								// To do : (This is a bug in Loxigen and the retentive builder is a workaround.)
								Match.Builder mb = sw.getOFFactory().buildMatch();
								Match.Builder reverseMb = sw.getOFFactory().buildMatch();
								mb.setExact(MatchField.ETH_SRC, srcMac)
								.setExact(MatchField.ETH_DST, dstMac);
								reverseMb.setExact(MatchField.ETH_SRC, dstMac)
								.setExact(MatchField.ETH_DST, srcMac);
								
								if (!vlan.equals(VlanVid.ZERO)) {
									mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
									reverseMb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
								}
								
								// To do : Detect switch type and match to create hardware-implemented flow
								// To do : Set option in config file to support specific or MAC-only matches
								if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
									IPv4 ip = (IPv4) eth.getPayload();
									IPv4Address srcIp = ip.getSourceAddress();
									IPv4Address dstIp = ip.getDestinationAddress();
									mb.setExact(MatchField.IPV4_SRC, srcIp)
									.setExact(MatchField.IPV4_DST, dstIp)
									.setExact(MatchField.ETH_TYPE, EthType.IPv4);
									reverseMb.setExact(MatchField.IPV4_SRC, dstIp)
									.setExact(MatchField.IPV4_DST, srcIp)
									.setExact(MatchField.ETH_TYPE, EthType.IPv4);
									
									if (ip.getProtocol().equals(IpProtocol.TCP)) {
										TCP tcp = (TCP) ip.getPayload();
										mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
										.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
										.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
										reverseMb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
										.setExact(MatchField.TCP_SRC, tcp.getDestinationPort())
										.setExact(MatchField.TCP_DST, tcp.getSourcePort());
									} else if (ip.getProtocol().equals(IpProtocol.UDP)) {
										UDP udp = (UDP) ip.getPayload();
										mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
										.setExact(MatchField.UDP_SRC, udp.getSourcePort())
										.setExact(MatchField.UDP_DST, udp.getDestinationPort());
										reverseMb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
										.setExact(MatchField.UDP_SRC, udp.getDestinationPort())
										.setExact(MatchField.UDP_DST, udp.getSourcePort());
									}	
								} else if (eth.getEtherType() == Ethernet.TYPE_ARP) {
									mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
									reverseMb.setExact(MatchField.ETH_TYPE, EthType.ARP);
								} 
								
								routeMatch = mb.build();
								reverseRouteMatch = reverseMb.build();
								
								/* End of match building */
								
								/* From here to assign group table */
								//创建组表
								createGroupByRoute(firstRoute, secondRoute, true);
								createGroupByRoute(firstRoute, secondRoute, false);
								//向链路中间节点下发流表
								pushFlowAddToIntermediateNodeByRoute(firstRoute, routeMatch, reverseRouteMatch, cookie);
								pushFlowAddToIntermediateNodeByRoute(secondRoute, routeMatch, reverseRouteMatch, cookie);
								//向目的节点下发流表和组表，再向源节点下发
								pushFlowAddToSrcAndDstSwitch(firstRoute, routeMatch, reverseRouteMatch, cookie);
								pushFlowAddToSrcAndDstSwitch(secondRoute, routeMatch, reverseRouteMatch, cookie);
								
								//FIXME:组表Id暂时粗略使用自加的策略(也许可以使用与packet一一对应的id策略)，即使这里使用double，依然存在溢出的bug。
								GROUP_NUM++;
								/* End of assigning group table */
								
								//将此packetIn数据包发送给目的主机相连交换机的出端口，否则，这个报文将丢失重传。
								pushPacket(switchService.getSwitch(dstDap.getSwitchDPID()), pi, false, dstDap.getPort(), cntx);
							}
							
						} else {
							log.error("The detached route list size is : " + tCDRouteList.size());
							return;
						}
					
					}
					iSrcDaps++;
					iDstDaps++;
				} else if (srcVsDest < 0) {
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
	
	/**
	 * 根据两条路由路径获取源目交换机上grouptable里的bucket，然后，下发OFGroupAdd消息到对应交换机
	 * @param firstRoute 工作路路由
	 * @param secondRoute 备份路路由
	 * @param isSrcSide 为true时对应路由路径源端桶和消息下发交换机，else为目的端
	 * @author ZX Peng
	 */
	private void createGroupByRoute(Route firstRoute, Route secondRoute, boolean isSrcSide) {
		ArrayList<OFBucket> buckets = new ArrayList<OFBucket>(2);
		IOFSwitch sw;
		List<NodePortTuple> firstNptList = firstRoute.getPath();
		List<NodePortTuple> secondNptList = secondRoute.getPath();
		int firstIndex = 0, secondIndex = 0;
		if(isSrcSide == true) {
			firstIndex = 1;
			secondIndex = 1;
			sw = switchService.getSwitch(firstRoute.getId().getSrc());
		} else {
			firstIndex = firstNptList.size() - 2;
			secondIndex = secondNptList.size() - 2;
			sw = switchService.getSwitch(firstRoute.getId().getDst());
		}
		NodePortTuple firstWatchNpt =  firstNptList.get(firstIndex);
		NodePortTuple secondWatchNpt = secondNptList.get(secondIndex);
		
		buckets.add(sw.getOFFactory().buildBucket()
				.setWatchPort(firstWatchNpt.getPortId())
				.setWatchGroup(OFGroup.ZERO)
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().buildOutput()
						.setMaxLen(0x0fFFffFF)
						.setPort(firstWatchNpt.getPortId())
						.build()))
						.build());
		buckets.add(sw.getOFFactory().buildBucket()
				.setWatchPort(secondWatchNpt.getPortId())
				.setWatchGroup(OFGroup.ZERO)
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().buildOutput()
						.setMaxLen(0x0fFFffFF)
						.setPort(secondWatchNpt.getPortId())
						.build()))
						.build());
		
		//push OFGroupAdd message to the switch
		//TODO: group number has to be distinct from each other
		OFGroupAdd groupAdd = sw.getOFFactory().buildGroupAdd()
			    .setGroup(OFGroup.of(GROUP_NUM))
			    .setGroupType(OFGroupType.FF)
			    .setBuckets(buckets)
			    .build();
			 
		sw.write(groupAdd);
	}
	
	/**
	 * 向路径中间节点下发流表修改消息
	 * @param route 路径路由
	 * @param routeMatch 正向匹配
	 * @param reverseRouteMatch 反向匹配
	 * @param cookie
	 * @author ZX Peng
	 */
	private void pushFlowAddToIntermediateNodeByRoute(Route route, Match routeMatch, Match reverseRouteMatch, U64 cookie) {
		
		List<NodePortTuple> pathList = route.getPath();
		
		//路径中间的流表下发
		for(int i=2; i<pathList.size()-2; i+=2) {
			NodePortTuple inputNpt = pathList.get(i);
			NodePortTuple outputNpt = pathList.get(i+1);
			IOFSwitch sw = switchService.getSwitch(inputNpt.getNodeId());
			OFPort inputPort = inputNpt.getPortId();
			OFPort outputPort = outputNpt.getPortId();
			
			if(sw == null) {
				log.error("Unable to push route, switch at DPID {} " + "not available", sw);
				return;
			}
			
			OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
			OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
			List<OFAction> actions = new ArrayList<OFAction>();
			Match.Builder matchBuilder = MatchUtils.createRetentiveBuilder(routeMatch);
			Match.Builder reverseMatchBuilder = MatchUtils.createRetentiveBuilder(reverseRouteMatch);
			matchBuilder.setExact(MatchField.IN_PORT, inputPort);
			reverseMatchBuilder.setExact(MatchField.IN_PORT, outputPort);
			
			aob.setPort(outputPort);
			aob.setMaxLen(Integer.MAX_VALUE);
			actions.add(aob.build());
			// compile
			fmb.setMatch(matchBuilder.build()) // was match w/o modifying input port
			.setActions(actions)
			.setIdleTimeout(0)
			.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
			.setBufferId(OFBufferId.NO_BUFFER)
			.setCookie(cookie)
			.setOutPort(outputPort)
			.setPriority(FLOWMOD_DEFAULT_PRIORITY);
			
			try {
				messageDamper.write(sw, fmb.build());
			} catch (IOException e) {
				log.error("message write error at switch : " + sw);
			}
			//reverse side
			aob.setPort(inputPort);
			aob.setMaxLen(Integer.MAX_VALUE);
			actions.add(aob.build());
			// compile
			fmb.setMatch(reverseMatchBuilder.build()) // was match w/o modifying input port
			.setActions(actions)
			.setIdleTimeout(0)
			.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
			.setBufferId(OFBufferId.NO_BUFFER)
			.setCookie(cookie)
			.setOutPort(inputPort)
			.setPriority(FLOWMOD_DEFAULT_PRIORITY);
			
			try {
				messageDamper.write(sw, fmb.build());
			} catch (IOException e) {
				log.error("message write error at switch : " + sw);
			}
		}
	}
	
	/**
	 * 向源目交换机发送组表和流表添加消息, 从路径后向前，先目后源下发消息. 注意, ovs版本必须2.3.1及以上，具体可参见以下链接:
	 * {@link https://floodlight.atlassian.net/wiki/display/floodlightcontroller/How+to+Work+with+Fast-Failover+OpenFlow+Groups}
	 * {@link http://www.sdnlab.com/3166.html}
	 * @param route 路由
	 * @param routeMatch 匹配
	 * @param reverseRouteMatch 反向匹配
	 * @param cookie
	 * @author ZX Peng
	 */
	private void pushFlowAddToSrcAndDstSwitch(Route route, Match routeMatch, Match reverseRouteMatch, U64 cookie) {
		List<NodePortTuple> nptList = route.getPath();
		if(nptList.size() < 4) {
			log.error("route {} size is smaller than 2" + route);
			return;
		}
		Match.Builder mb = MatchUtils.createRetentiveBuilder(routeMatch);
		Match.Builder reverseMb = MatchUtils.createRetentiveBuilder(reverseRouteMatch);
		//目的端流表和组表设置
		NodePortTuple inNpt = nptList.get(nptList.size() - 1);
		NodePortTuple outNpt = nptList.get(nptList.size() - 2);
		IOFSwitch sw = switchService.getSwitch(inNpt.getNodeId());

		mb.setExact(MatchField.IN_PORT, outNpt.getPortId());
		reverseMb.setExact(MatchField.IN_PORT, inNpt.getPortId());
		
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
		List<OFAction> actions = new ArrayList<OFAction>();
		
		aob.setPort(inNpt.getPortId());
		aob.setMaxLen(Integer.MAX_VALUE);
		actions.add(aob.build());
		// compile
		fmb.setMatch(mb.build()) // was match w/o modifying input port
		.setActions(actions)
		.setIdleTimeout(0)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setCookie(cookie)
		.setOutPort(inNpt.getPortId())
		.setPriority(FLOWMOD_DEFAULT_PRIORITY);
		try {
			messageDamper.write(sw, fmb.build());
		} catch (IOException e) {
			log.error("Unable to send message to the switch {} " + sw);
		}
		
		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
				.setCookie(cookie)
				.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
				.setIdleTimeout(0)
				.setPriority(FlowModUtils.PRIORITY_MAX)
				.setMatch(reverseMb.build())
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().buildGroup()
							.setGroup(OFGroup.of(GROUP_NUM))
							.build()))
				.build();

		try {
			messageDamper.write(sw, flowAdd);
		} catch (IOException e) {
			log.error("Unable to send message to the switch {} " + sw);
		}
		
		//源端流表和组表设置
		inNpt = nptList.get(0);
		outNpt = nptList.get(1);
		sw = switchService.getSwitch(inNpt.getNodeId());

		mb.setExact(MatchField.IN_PORT, inNpt.getPortId());
		reverseMb.setExact(MatchField.IN_PORT, outNpt.getPortId());
		
		fmb = sw.getOFFactory().buildFlowAdd();
		aob = sw.getOFFactory().actions().buildOutput();
		actions = new ArrayList<OFAction>();
		
		aob.setPort(inNpt.getPortId());
		aob.setMaxLen(Integer.MAX_VALUE);
		actions.add(aob.build());
		// compile
		fmb.setMatch(reverseMb.build()) // was match w/o modifying input port
		.setActions(actions)
		.setIdleTimeout(0)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setCookie(cookie)
		.setOutPort(inNpt.getPortId())
		.setPriority(FLOWMOD_DEFAULT_PRIORITY);
		try {
			messageDamper.write(sw, fmb.build());
		} catch (IOException e) {
			log.error("Unable to send message to the switch {} " + sw);
		}
		
		flowAdd = sw.getOFFactory().buildFlowAdd()
				.setCookie(cookie)
				.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
				.setIdleTimeout(0)
				.setPriority(FlowModUtils.PRIORITY_MAX)
				.setMatch(mb.build())
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().buildGroup()
							.setGroup(OFGroup.of(GROUP_NUM))
							.build()))
				.build();

		try {
			messageDamper.write(sw, flowAdd);
		} catch (IOException e) {
			log.error("Unable to send message to the switch {} " + sw);
		}
		
	}
	
	@LogMessageDoc(level="ERROR",
			message="Failure writing drop flow mod",
			explanation="An I/O error occured while trying to write a " +
					"drop flow mod to a switch",
					recommendation=LogMessageDoc.CHECK_SWITCH)
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
	
	/**
	 * Creates a OFPacketOut with the OFPacketIn data that is flooded on all ports unless
	 * the port is blocked, in which case the packet will be dropped.
	 * @param sw The switch that receives the OFPacketIn
	 * @param pi The OFPacketIn that came to the switch
	 * @param cntx The FloodlightContext associated with this OFPacketIn
	 */
	@LogMessageDoc(level="ERROR",
			message="Failure writing PacketOut " +
					"switch={switch} packet-in={packet-in} " +
					"packet-out={packet-out}",
					explanation="An I/O error occured while writing a packet " +
							"out message to the switch",
							recommendation=LogMessageDoc.CHECK_SWITCH)
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

	// ****************
	// IOFMessageListener
	// ****************
	
	@Override
	public String getName() {
		return ProtectionForwarding.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
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
		//System.out.println("single link failure!");
		//TODO: From here to handle link failure
	}
	
}
