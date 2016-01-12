package net.floodlightcontroller.failover;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IFailureDiscoveryService extends IFloodlightService{
	
    /**
     * Adds a listener to listen for IFailureDiscoveryService messages
     * @param listener The listener that wants the notifications
     */
	public void addListener(IFailureDiscoveryListener listener);

}
