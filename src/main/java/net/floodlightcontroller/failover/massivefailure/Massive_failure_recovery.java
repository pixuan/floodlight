package net.floodlightcontroller.failover.massivefailure;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import net.floodlightcontroller.failover.massivefailure.GetDevices.PortDevice;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFFlowStatsRequest.Builder;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.failover.massivefailure.IGetDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;

public class Massive_failure_recovery implements IFloodlightModule,IMassiveFailureRecoveryService {
	protected static Logger log =
			LoggerFactory.getLogger(Massive_failure_recovery.class);
	protected IFloodlightProviderService floodlightProviderService;
	protected ITopologyService topologyService;
	protected IOFSwitchService switchService;
	protected ILinkDiscoveryService linkdiscoveryservice;
	protected IGetDeviceService getdeviceservice;
	
	protected OFMessageDamper messageDamper;
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	
	public static final short FLOWMOD_DEFAULT_IDLE_TIMEOUT_CONSTANT = 0;
	public static final short FLOWMOD_DEFAULT_HARD_TIMEOUT_CONSTANT = 0;
	
	public static int FLOWMOD_DEFAULT_PRIORITY = 1; 

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IMassiveFailureRecoveryService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>,
		IFloodlightService> m =
		new HashMap<Class<? extends IFloodlightService>,
		IFloodlightService>();
		// We are the class that implements the service
		m.put(IMassiveFailureRecoveryService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ITopologyService.class);
		l.add(ILinkDiscoveryService.class);
		l.add(IGetDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		this.switchService = context.getServiceImpl(IOFSwitchService.class);
		this.linkdiscoveryservice = context.getServiceImpl(ILinkDiscoveryService.class);
		this.getdeviceservice = context.getServiceImpl(IGetDeviceService.class);
		
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub

	}

	@Override
	public void startmassiverecovery() {
		//
		long massiveRecoveryBegin = System.nanoTime();
		//
		
		Map<DatapathId, Set<Link>> dpidtolink = linkdiscoveryservice.getSwitchLinks();
		Set<DatapathId> switches = switchService.getAllSwitchDpids();
		//
		DatapathId root = getrootnode(switches);
		if(root==null)
			log.error("no root node");
		HashMap<DatapathId, Link> nexthoplinks = new HashMap<DatapathId, Link>();
		Stack<DatapathId> nodestack = new Stack<DatapathId>();
		
		//
		long spanningTreeBegin = System.nanoTime();
		//
		
		//代表是根还是叶子节点
		HashMap<DatapathId,Integer> seen = new HashMap<DatapathId,Integer>();
		//广度优先遍历，获取一颗以root为根的树
		Queue<DatapathId> nodeq = new LinkedList<DatapathId>();
		nodeq.add(root);
		while(!nodeq.isEmpty()){
			DatapathId node=nodeq.poll();
			nodestack.push(node);
			if(!dpidtolink.containsKey(node)){
				log.error("can not found switch in topo");
				break;
			}
			Set<Link> links = dpidtolink.get(node);
			for(Link link : links){
				DatapathId src = link.getSrc();
				if(src != node && !seen.containsKey(src)){
					seen.put(node, 0);
					seen.put(src, 1);
					nexthoplinks.put(src, link);
					log.info("src is {} next hop is {}",node,src);
					nodeq.add(src);
				}
			}
		}
		seen.put(root, -1);
		
		//
		long spanningTreeEnd = System.nanoTime();
		log.info("spanningTreeBegin : " + spanningTreeBegin);
		log.info("spanningTreeEnd : " + spanningTreeEnd);
		log.info("spanningTreeTime : " + (spanningTreeEnd - spanningTreeBegin));
		//
		
		//
		long flowModBegin = System.nanoTime();
		//
		
		Map<DatapathId,List<PortDevice>> fakedpidtodevice = new HashMap<DatapathId,List<PortDevice>>();
		while(!nodestack.isEmpty()){
			DatapathId node = nodestack.pop();
			List<PortDevice> devicelists = new ArrayList<PortDevice>();
			int nodepos = seen.get(node);
			if(nodepos == 1)
				devicelists = getdeviceservice.getdevicefromDPID(node);
			else{
				//log.info("node {} fake device list map is {}",node,fakedpidtodevice);
				if(fakedpidtodevice.containsKey(node))
					devicelists = fakedpidtodevice.get(node);
				else
					devicelists = getdeviceservice.getdevicefromDPID(node);
			}
				
			//log.info("node {} device lists is {}",node,devicelists);
			if(devicelists==null || devicelists.isEmpty()) continue;
			//根节点只有下行
			if(nodepos == -1){
				for(int i=0; i<devicelists.size(); i++){
					PortDevice portdevice = devicelists.get(i);
					OFPort port = portdevice.getport();
					IDevice device = portdevice.getdevice();
					Match.Builder mb = switchService.getSwitch(node).getOFFactory().buildMatch();
					mb.setExact(MatchField.ETH_DST,device.getMACAddress());
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
					AddFlow(node,mb,port,1);
					//log.info(" node{} install flow entry At root output is{}",node, port);
				}
				break;
			}
			//普通和叶子节点，既有上行，又有下行
			for(int i=0; i<devicelists.size(); i++){
				PortDevice portdevice = devicelists.get(i);
				OFPort port = portdevice.getport();
				IDevice device = portdevice.getdevice();
				Link lk = nexthoplinks.get(node);
				DatapathId dst = lk.getDst();
				OFPort dstport = lk.getDstPort();
				OFPort srcport = lk.getSrcPort();
				Match.Builder mb1 = switchService.getSwitch(node).getOFFactory().buildMatch();
				mb1.setExact(MatchField.IN_PORT, port);
				mb1.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				AddFlow(node,mb1,srcport,1);
				//log.info(" node{} install flow entry to root output is{}",node, port);
				Match.Builder mb2 = switchService.getSwitch(node).getOFFactory().buildMatch();
				mb2.setExact(MatchField.ETH_DST,device.getMACAddress());
				mb2.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				//log.info(" node{} install flow entry to hosts output is{}",node, port);
				AddFlow(node,mb2,port,3);
				portdevice.setport(dstport);
				addnewdevice(fakedpidtodevice,dst,portdevice);
			}
			
		}
		
		//
		long flowModEnd = System.nanoTime();
		log.info("flowModBegin : " + flowModBegin);
		log.info("flowModEnd : " + flowModEnd);
		log.info("flowModTime : " + (flowModEnd - flowModBegin));
		//
		//
		long massiveRecoveryEnd = System.nanoTime();
		log.info("massiveRecoveryBegin : " + massiveRecoveryBegin);
		log.info("massiveRecoveryEnd : " + massiveRecoveryEnd);
		log.info("massiveRecoveryTime : " + (massiveRecoveryEnd - massiveRecoveryBegin));
		//
		
	}
	
	private void addnewdevice(Map<DatapathId,List<PortDevice>> target, DatapathId sw, PortDevice value){
		if(target.containsKey(sw))
			target.get(sw).add(value);
		else{
			List<PortDevice> templist = getdeviceservice.getdevicefromDPID(sw);
			if(templist == null){
				templist = new ArrayList<PortDevice>();
				templist.add(value);
			}
			else
				templist.add(value);
			target.put(sw, templist);
		}
		//log.info("add device for sw {} device list is {}",sw,target);
	}
	
	private void AddFlow(DatapathId node, Match.Builder match, OFPort outport, int priority){
		
		IOFSwitch sw = switchService.getSwitch(node);
		org.projectfloodlight.openflow.protocol.OFFlowAdd.Builder flowadd = sw.getOFFactory().buildFlowAdd();
		OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
		List<OFAction> actions = new ArrayList<OFAction>();
		aob.setPort(outport);
		aob.setMaxLen(Integer.MAX_VALUE);
		actions.add(aob.build());
		flowadd.setMatch(match.build()) // was match w/o modifying input port
		.setActions(actions)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT_CONSTANT)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT_CONSTANT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setPriority(FLOWMOD_DEFAULT_PRIORITY+priority);
		try{
			messageDamper.write(switchService.getSwitch(node), flowadd.build());
			
		}catch(IOException e){
			log.error("Failure writing flow mod", e);
		}
	}
	
	/**
	 * 根据每个节点总共转发了多少字节的报文来选取root
	 * @param switches
	 * @return
	 */
	protected DatapathId getrootnode(Set<DatapathId> switches){
		//
		long flowLookupBegin = System.nanoTime();
		//
		
		DatapathId root=null;
		long rootflow = -1;
		for(DatapathId swid : switches){
			IOFSwitch sw = switchService.getSwitch(swid);
			ListenableFuture<?> TableFuture = null;
			List<OFFlowStatsReply> values = null;
			Builder flowreq = sw.getOFFactory().buildFlowStatsRequest();
			flowreq.setTableId(TableId.ZERO);
			
			try{
				TableFuture = sw.writeStatsRequest(flowreq.build());
				values = (List<OFFlowStatsReply>) TableFuture.get(2, TimeUnit.SECONDS);
				
				/*
				 * 下一步统计发包数量时，可以不删除原始流表。
				 */
				
				long bytecount = sumflows(swid,values);
				//log.info("sw {} byte count is {}",swid,bytecount);
				if(bytecount>rootflow){
					Set<OFPort> ports = topologyService.getPortsWithLinks(swid);
					
					//log.info("sw {} port size is {}",swid,ports.size());
					if(ports.size()>1){
						rootflow=bytecount;
						root=swid;
					}
						 
				}
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
		//
		long flowLookupEnd = System.nanoTime();
		log.info("flowLookupBegin : " + flowLookupBegin);
		log.info("flowLookupEnd : " + flowLookupEnd);
		log.info("flowLookupTime : " + (flowLookupEnd - flowLookupBegin));
		//
		return root;
	}
	
	/**
	 * 统计发包数量。这里删除原始流表项可以删除。因为之后会下发优先级更高的流表项。
	 * @param sw
	 * @param values
	 * @return
	 */
	protected long sumflows(DatapathId sw, List<OFFlowStatsReply> values){
		long sum=0;
		OFFlowStatsReply value=values.get(0);
		List<OFFlowStatsEntry> entries = value.getEntries();
		for(OFFlowStatsEntry entry: entries){
			long bc = entry.getByteCount().getValue();
			sum += bc;
			deleteflowentry(sw,entry);
		}
		return sum;
	}
	
	/**
	 * 删除原始流表项
	 * @param src
	 * @param entry
	 */
	private void deleteflowentry(DatapathId src,OFFlowStatsEntry entry){
		OFFlowMod.Builder fmb = switchService.getSwitch(src).getOFFactory().buildFlowDelete();
		fmb.setMatch(entry.getMatch())
		//.setActions(entry.getActions())
		.setActions(((OFInstructionApplyActions)entry.getInstructions().get(0)).getActions())
		.setIdleTimeout(entry.getIdleTimeout())
		.setHardTimeout(entry.getHardTimeout());
		switchService.getSwitch(src).write(fmb.build());
	}

}
