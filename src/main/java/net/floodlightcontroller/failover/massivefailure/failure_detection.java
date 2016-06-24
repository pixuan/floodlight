package net.floodlightcontroller.failover.massivefailure;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFFlowStatsRequest.Builder;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.LDUpdate;
import net.floodlightcontroller.linkdiscovery.ILinkDiscovery.UpdateOperation;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.OFMessageDamper;

public class failure_detection implements IFloodlightModule, ITopologyListener,
			IOFMessageListener {
	protected static Logger log =
			LoggerFactory.getLogger(failure_detection.class);
	
	protected IFloodlightProviderService floodlightProviderService;
	protected ITopologyService topologyService;
	protected IRoutingService routingEngineService;
	protected IOFSwitchService switchService;
	protected IMassiveFailureRecoveryService massivefailurerecoveryservice;
	
	protected boolean SpanTreeRecovery= false;
	protected int faillinks_num;
	protected short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 25;
	
	protected OFMessageDamper messageDamper;
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms

	@Override
	public void topologyChanged(List<LDUpdate> linkUpdates) {
		// TODO Auto-generated method stub
		if(!linkUpdates.isEmpty()){
			Iterator<LDUpdate> update = linkUpdates.iterator();
			while(update.hasNext()){
				LDUpdate key = update.next();
				UpdateOperation operation = key.getOperation();
				if(operation == UpdateOperation.LINK_REMOVED && SpanTreeRecovery ==false){
					SpanTreeRecovery =true;
					//massivefailurerecoveryservice.startmassiverecovery();
				}
					
					//this.link_failure_handle(key);
			}
		}

	}
	
	private void link_failure_handle(LDUpdate link){
		faillinks_num++;
		DatapathId srcid = link.getSrc();
		OFPort srcport = link.getSrcPort();
		IOFSwitch src=switchService.getSwitch(srcid);
		ListenableFuture<?> TableFuture = null;
		List<OFFlowStatsReply> values = null;
		Builder flowreq = src.getOFFactory().buildFlowStatsRequest();
		flowreq.setTableId(TableId.ZERO);
		//ListenableFuture<?> TableFuture;
		
		try{
			TableFuture = src.writeStatsRequest(flowreq.build());
			log.info("request xid is {}",faillinks_num);
			values = (List<OFFlowStatsReply>) TableFuture.get(2, TimeUnit.SECONDS);
			boolean flag = linkrecovery(srcid, srcport,link.getDst(),values);
			if(flag)
				log.info("src£º{} have recovery",srcid);
		}catch (InterruptedException e) {
			log.info("PeriodExecute:InterruptedException");
			e.printStackTrace();
		} catch (ExecutionException e) {
			log.info("PeriodExecute:ExecutionException");
			e.printStackTrace();
		} catch (TimeoutException e) {
			log.info("PeriodExecute:TimeoutException");
			e.printStackTrace();
		}				
	}			

	private boolean linkrecovery(DatapathId src,OFPort srcport,DatapathId dst, List<OFFlowStatsReply> values){
		Route route = this.routingEngineService.getRoute(src, dst, U64.of(0));
		if (route == null){
			log.error("failed find another path for {} to {}",src,dst);
			return false;
		}
		if (values.size() == 0 || values.size() > 1){
			log.error("get flow entry error size is {}",values.size());
		}
		OFFlowStatsReply value = values.get(0);
	
		List<OFFlowStatsEntry> entries = value.getEntries();
		Iterator<OFFlowStatsEntry> itor = entries.iterator();
		while(itor.hasNext()){
			OFFlowStatsEntry entry = itor.next();
			Match match = entry.getMatch();
			OFPort inport = match.get(MatchField.IN_PORT);
			if(inport == srcport){
				Match.Builder mb = match.createBuilder();
				mb.wildcard(MatchField.IN_PORT);
				OFFlowMod.Builder fmb = switchService.getSwitch(src).getOFFactory().buildFlowAdd();
				fmb.setMatch(mb.build())
				.setActions(entry.getActions())
				.setCookie(entry.getCookie())
				.setHardTimeout(entry.getHardTimeout())
				.setIdleTimeout(35)
				.setPriority(5);
				try{
					messageDamper.write(switchService.getSwitch(src), fmb.build());
					log.info("1 change flow entry to {}, sw is {}",fmb.build(),src);
				}catch(IOException e){
					log.error("Failure writing flow mod", e);
				}
				//deleteflowentry(src,entry);
				
			}
			List<OFAction> listactions = entry.getActions();
			List<OFAction> actions = new ArrayList<OFAction>(listactions);
			for(int j=0; j<actions.size(); j++){
				OFAction action = actions.get(j);
				if (action instanceof OFActionOutput){
					OFPort outport = ((OFActionOutput) action).getPort();
					if (outport == srcport){
						log.info("path is {}",route);
						actions.remove(j);
						List<NodePortTuple> nodeport = route.getPath();
						for(int i=0; i<nodeport.size()-1; i+=2){
							List<OFAction> temp_actions = new ArrayList<OFAction>(actions);
							log.info("temp action is {},actions is {}",temp_actions,actions);
							DatapathId nodeid = nodeport.get(i).getNodeId();
							OFPort portid = nodeport.get(i).getPortId();
							OFActionOutput.Builder aob = switchService.getSwitch(nodeid).getOFFactory().actions().buildOutput();
							aob.setPort(portid);
							aob.setMaxLen(Integer.MAX_VALUE);
							temp_actions.add(aob.build());
							OFFlowMod.Builder fmb = switchService.getSwitch(nodeid).getOFFactory().buildFlowAdd();
							Match.Builder mb = match.createBuilder();
							if (i==0)
								mb.setExact(MatchField.IN_PORT, inport);
							else
								mb.setExact(MatchField.IN_PORT, nodeport.get(i-1).getPortId());
							fmb.setMatch(mb.build())
							.setActions(temp_actions)
							.setCookie(entry.getCookie())
							.setHardTimeout(entry.getHardTimeout())
							.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
							.setPriority(5);
							try{
								messageDamper.write(switchService.getSwitch(nodeid), fmb.build());
								log.info("2 change flow entry to {}, sw is {}",fmb.build(),nodeid);
							}catch(IOException e){
								log.error("Failure writing flow mod", e);
							}
							//switchService.getSwitch(src).write(fmb.build());
						}
						deleteflowentry(src,entry);
						break;
					}
				}
			}
			
		}
		return true;
	}
	
	private void deleteflowentry(DatapathId src,OFFlowStatsEntry entry){
		OFFlowMod.Builder fmb = switchService.getSwitch(src).getOFFactory().buildFlowDelete();
		fmb.setMatch(entry.getMatch()) 
		.setActions(entry.getActions())
		.setIdleTimeout(entry.getIdleTimeout())
		.setHardTimeout(entry.getHardTimeout());
		switchService.getSwitch(src).write(fmb.build());
	}
	//[OFFlowStatsReplyVer10(xid=164, flags=[], entries=[OFFlowStatsEntryVer10(tableId=0x0, match=OFMatchV1Ver10(in_port=3, eth_src=a6:a0:d0:0a:7e:df, eth_dst=de:28:55:a5:8e:4b, eth_type=800, ipv4_src=10.0.0.1, ipv4_dst=10.0.0.2), durationSec=8, durationNsec=191000000, priority=1, idleTimeout=25, hardTimeout=0, cookie=0x0020000000000000, packetCount=0x0000000000000008, byteCount=0x0000000000000310, actions=[OFActionOutputVer10(port=4, maxLen=65535)]),
	  //                                                 OFFlowStatsEntryVer10(tableId=0x0, match=OFMatchV1Ver10(in_port=4, eth_src=de:28:55:a5:8e:4b, eth_dst=a6:a0:d0:0a:7e:df, eth_type=800, ipv4_src=10.0.0.2, ipv4_dst=10.0.0.1), durationSec=8, durationNsec=190000000, priority=1, idleTimeout=25, hardTimeout=0, cookie=0x0020000000000000, packetCount=0x0000000000000007, byteCount=0x00000000000002ae, actions=[OFActionOutputVer10(port=3, maxLen=65535)]), 
	     //                                              OFFlowStatsEntryVer10(tableId=0x0, match=OFMatchV1Ver10(in_port=3, eth_src=a6:a0:d0:0a:7e:df, eth_dst=de:28:55:a5:8e:4b, eth_type=806), durationSec=3, durationNsec=178000000, priority=1, idleTimeout=25, hardTimeout=0, cookie=0x0020000000000000, packetCount=0x0000000000000001, byteCount=0x000000000000002a, actions=[OFActionOutputVer10(port=4, maxLen=65535)]), 
	      //                                             OFFlowStatsEntryVer10(tableId=0x0, match=OFMatchV1Ver10(in_port=4, eth_src=de:28:55:a5:8e:4b, eth_dst=a6:a0:d0:0a:7e:df, eth_type=806), durationSec=8, durationNsec=194000000, priority=1, idleTimeout=25, hardTimeout=0, cookie=0x0020000000000000, packetCount=0x0000000000000001, byteCount=0x000000000000002a, actions=[OFActionOutputVer10(port=3, maxLen=65535)])])]
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
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ITopologyService.class);
		l.add(IRoutingService.class);
		l.add(IMassiveFailureRecoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		this.switchService = context.getServiceImpl(IOFSwitchService.class);
		this.routingEngineService = context.getServiceImpl(IRoutingService.class);
		this.massivefailurerecoveryservice = context.getServiceImpl(IMassiveFailureRecoveryService.class);
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
		this.faillinks_num = 0;
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, this);
		topologyService.addListener(this);
		
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "failure detection";
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
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		//Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	    log.info("have receive flow stat from sw {}",sw);
		return Command.CONTINUE;
	}

}
