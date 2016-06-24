package net.floodlightcontroller.failover.massivefailure;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
//import java.util.Iterator;
//import java.util.Date;










import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;











import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;


public class GetDevices implements IFloodlightModule, IDeviceListener,IGetDeviceService {
	protected static Logger logger = LoggerFactory.getLogger(GetDevices.class);
	protected IDeviceService devicemanager;
	protected Map<Long,IDevice> Devicelist;
	protected Map<DatapathId,List<PortDevice>> switchtodevice;

	public class PortDevice{
		OFPort port;
		IDevice device;
		PortDevice(OFPort port, IDevice device){
			this.port = port;
			this.device = device;
		}
		public OFPort getport(){
			return this.port;
		}
		public IDevice getdevice(){
			return this.device;
		}
		public void setport(OFPort port){
			this.port = port;
		}
		@Override
	    public boolean equals(Object obj) {
			if (this == obj) return true;
	        if (obj == null) return false;
	        if (getClass() != obj.getClass()) return false;
	        PortDevice other = (PortDevice) obj;
	        if (!port.equals(other.port)) return false;
	        if (!device.equals(other.device)) return false;
	        return true;
		}
		@Override
	    public String toString() {
	        StringBuilder builder = new StringBuilder();
	        builder.append("Port :");
	        builder.append(port);
	        builder.append(", device :");
	        builder.append(device.getDeviceKey());
	        builder.append(", MAC :");
	        builder.append(device.getMACAddressString());
	        return builder.toString();
	    }
		
	}
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return GetDevices.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) {
		// TODO Auto-generated method stub
		return false;
	}
	
	protected void showdevice(IDevice device){
		//Iterator<IDevice> keys = Devicelist.values().iterator();
		//Date d = new Date();
		//System.out.println(d);
		//System.out.print(keys);
		//while (keys.hasNext()){
			//IDevice device = keys.next();
			logger.info("device is id {} mac is {}",
					device.getDeviceKey().toString(),
					device.getMACAddressString());
			logger.info("ip is {}",device.getIPv4Addresses());
			logger.info("switch is {}",device.getAttachmentPoints());
		//}
		
	}

	@Override
	public void deviceAdded(IDevice device) {
		// TODO Auto-generated method stub
		Long keyID = device.getDeviceKey();
		SwitchPort[] swports = device.getAttachmentPoints();
		SwitchPort swport = swports[swports.length-1];
		DatapathId sw = swport.getSwitchDPID();
		OFPort port = swport.getPort();
		logger.info("add new device at sw {} port{}",sw,swport);
		PortDevice pd = new PortDevice(port,device);
		if(switchtodevice.containsKey(sw)){
			if(!switchtodevice.get(sw).contains(pd))
				switchtodevice.get(sw).add(pd);
		}
		else{
			List<PortDevice> listpd = new ArrayList<PortDevice>();
			listpd.add(pd);
			switchtodevice.put(sw, listpd);
		}
		Devicelist.put(keyID, device);
		this.showdevice(device);

	}

	@Override
	public void deviceRemoved(IDevice device) {
		// TODO Auto-generated method stub
		Long keyID = device.getDeviceKey();
		SwitchPort[] swports = device.getAttachmentPoints();
		SwitchPort swport = swports[swports.length-1];
		DatapathId sw = swport.getSwitchDPID();
		if(switchtodevice.containsKey(sw)){
			OFPort port = swport.getPort();
			PortDevice pd = new PortDevice(port,device);
			if(switchtodevice.get(sw).contains(pd))
				switchtodevice.get(sw).remove(pd);
		}
		if(Devicelist.containsKey(keyID)){
			logger.info("deivce {} removed",keyID);
			Devicelist.remove(keyID);
		}
		this.showdevice(device);

	}

	@Override
	public void deviceMoved(IDevice device) {
		// TODO Auto-generated method stub
		logger.info("device moved {}",device.getDeviceKey());
		Long keyID = device.getDeviceKey();
		SwitchPort[] newswports = device.getAttachmentPoints();
		SwitchPort[] oldswports = device.getOldAP();
		if (oldswports!=null && oldswports.length != 0){
			SwitchPort oldswport = oldswports[oldswports.length-1];
			DatapathId oldsw = oldswport.getSwitchDPID();
			logger.info("device {} move from sw {} ",keyID, oldsw);
			if(switchtodevice.containsKey(oldsw)){
				OFPort port = oldswport.getPort();
				PortDevice pd = new PortDevice(port,device);
				if(switchtodevice.get(oldsw).contains(pd))
					switchtodevice.get(oldsw).remove(pd);
			}
		}
		if(newswports!=null && newswports.length !=0){
			SwitchPort newswport = newswports[newswports.length-1];
			DatapathId newsw = newswport.getSwitchDPID();
			logger.info("device {} move to sw{}",keyID, newsw);
			if(switchtodevice.containsKey(newsw)){
				OFPort port = newswport.getPort();
				PortDevice pd = new PortDevice(port,device);
				if(!switchtodevice.get(newsw).contains(pd))
					switchtodevice.get(newsw).add(pd);
			}
			else{
				OFPort port = newswport.getPort();
				PortDevice pd = new PortDevice(port,device);
				List<PortDevice> listpd = new ArrayList<PortDevice>();
				listpd.add(pd);
				switchtodevice.put(newsw, listpd);
			}
		}
		if (Devicelist.containsKey(keyID)){
			logger.info("from {} to {}",Devicelist.get(keyID).getAttachmentPoints(),
					device.getAttachmentPoints());
			Devicelist.put(keyID, device);
		}
	}

	@Override
	public void deviceIPV4AddrChanged(IDevice device) {
		// TODO Auto-generated method stub
		logger.info("device{} ip change to {}",device.getDeviceKey(),device.getIPv4Addresses());
		Long keyID = device.getDeviceKey();
		if(Devicelist.containsKey(keyID)){
			Devicelist.put(keyID,device);
		}

	}

	@Override
	public void deviceVlanChanged(IDevice device) {
		// TODO Auto-generated method stub

	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IGetDeviceService.class);
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
		m.put(IGetDeviceService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		//完善getModuleDependencies() 告知加载器在floodlight启动时将自己加载
		Collection<Class<?extends IFloodlightService>> l= 
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// 加载依赖关系并初始化数据结构
		devicemanager = context.getServiceImpl(IDeviceService.class);
		Devicelist = new HashMap<Long, IDevice>();
		switchtodevice = new HashMap<DatapathId,List<PortDevice>>();
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// 消息需在startup方法中被记录和注册，同时确认新增模块需要依赖的其他模块已被正常初始化
		devicemanager.addListener(this);
	
	}

	@Override
	public List<PortDevice> getdevicefromDPID(DatapathId sw) {
		// TODO Auto-generated method stub
		//logger.info("test switchtodevice is {}",this.switchtodevice);
		return this.switchtodevice.get(sw);
		
	}

}
