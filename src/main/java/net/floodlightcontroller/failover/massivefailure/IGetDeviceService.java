package net.floodlightcontroller.failover.massivefailure;

import java.util.List;

import org.projectfloodlight.openflow.types.DatapathId;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.failover.massivefailure.GetDevices.PortDevice;

public interface IGetDeviceService extends IFloodlightService {

	public List<PortDevice> getdevicefromDPID(DatapathId sw);
}
