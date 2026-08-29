"""
Packet capture module using Scapy.

This module handles network packet capture with the following considerations:
- Cross-platform compatibility (Windows/Linux/Mac)
- Privilege requirements (admin/root for raw socket access)
- Capture filters using BPF syntax
- Performance considerations for high-traffic networks
- Safety: bounded capture to prevent resource exhaustion

On Windows, this requires Npcap to be installed:
https://npcap.com/

On Linux, this requires libpcap to be installed.
"""

import logging
from typing import Optional, Callable, Any
from threading import Thread, Event
import queue
import time

from scapy.all import sniff, get_if_list, get_if_addr
from scapy.packet import Packet

from app.config.settings import settings
from app.protocols.parser import parser
from app.models.packet import ParsedPacket

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Manages network packet capture using Scapy.
    
    This class provides:
    1. Interface enumeration and selection
    2. Packet capture with BPF filtering
    3. Real-time packet processing via callback
    4. Thread-safe operation for background capture
    5. Graceful start/stop lifecycle management
    
    The capture is designed to be non-blocking for the main application
    by running in a separate thread and using a queue for packet delivery.
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        capture_filter: str = "tcp or udp",
        packet_callback: Optional[Callable[[ParsedPacket], None]] = None,
    ):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface name (None for default)
            capture_filter: BPF filter string (e.g., "tcp port 80")
            packet_callback: Function to call for each parsed packet
        """
        self.interface = interface or settings.capture_interface
        self.capture_filter = capture_filter or settings.capture_filter
        self.packet_callback = packet_callback
        
        # Capture state
        self.is_capturing = False
        self.capture_thread: Optional[Thread] = None
        self.stop_event = Event()
        
        # Statistics
        self.packets_captured = 0
        self.packets_processed = 0
        self.start_time: Optional[float] = None
        
        # Packet queue for processing
        self.packet_queue: queue.Queue = queue.Queue(maxsize=1000)
        
        logger.info(f"Initialized PacketCapture on interface: {self.interface}")
        logger.info(f"Capture filter: {self.capture_filter}")
    
    @staticmethod
    def list_interfaces() -> list[str]:
        """
        List available network interfaces.
        
        Returns:
            List of interface names
        """
        try:
            interfaces = get_if_list()
            logger.info(f"Available interfaces: {interfaces}")
            return interfaces
        except Exception as e:
            logger.error(f"Failed to list interfaces: {e}")
            return []
    
    @staticmethod
    def get_interface_ip(interface: str) -> Optional[str]:
        """
        Get the IP address of a specific interface.
        
        Args:
            interface: Interface name
            
        Returns:
            IP address or None if not found
        """
        try:
            ip = get_if_addr(interface)
            return ip
        except Exception as e:
            logger.error(f"Failed to get IP for interface {interface}: {e}")
            return None
    
    def _packet_handler(self, raw_packet: Packet) -> None:
        """
        Internal handler for each captured packet.
        
        This method is called by Scapy for each packet matching the filter.
        It parses the packet and queues it for processing.
        
        Args:
            raw_packet: Raw Scapy packet
        """
        self.packets_captured += 1
        
        # Parse the packet
        parsed_packet = parser.parse_packet(raw_packet)
        
        if parsed_packet:
            # Queue for processing (non-blocking)
            try:
                self.packet_queue.put_nowait(parsed_packet)
            except queue.Full:
                logger.warning("Packet queue full, dropping packet")
        else:
            logger.debug("Failed to parse packet")
    
    def _process_packets(self) -> None:
        """
        Process packets from the queue in a separate thread.
        
        This method runs in a separate thread and processes packets
        from the queue, calling the registered callback for each.
        """
        while not self.stop_event.is_set() or not self.packet_queue.empty():
            try:
                # Get packet with timeout to allow checking stop_event
                packet = self.packet_queue.get(timeout=0.1)
                
                self.packets_processed += 1
                
                # Call the registered callback
                if self.packet_callback:
                    try:
                        self.packet_callback(packet)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")
                
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    def start(self) -> bool:
        """
        Start packet capture.
        
        Returns:
            True if capture started successfully, False otherwise
        """
        if self.is_capturing:
            logger.warning("Capture already running")
            return False
        
        try:
            # Reset state
            self.stop_event.clear()
            self.packets_captured = 0
            self.packets_processed = 0
            self.start_time = time.time()
            
            # Start packet processing thread
            self.capture_thread = Thread(target=self._process_packets, daemon=True)
            self.capture_thread.start()
            
            # Start packet capture with Scapy
            # Note: This is a blocking call, so we run it in a thread
            def capture_loop():
                try:
                    sniff(
                        iface=self.interface,
                        filter=self.capture_filter,
                        prn=self._packet_handler,
                        stop_filter=lambda x: self.stop_event.is_set(),
                        store=False,  # Don't store packets in memory
                    )
                except Exception as e:
                    logger.error(f"Capture error: {e}")
                    self.is_capturing = False
            
            capture_thread = Thread(target=capture_loop, daemon=True)
            capture_thread.start()
            
            self.is_capturing = True
            logger.info(f"Started packet capture on {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            return False
    
    def stop(self) -> None:
        """Stop packet capture gracefully."""
        if not self.is_capturing:
            return
        
        logger.info("Stopping packet capture...")
        self.stop_event.set()
        self.is_capturing = False
        
        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5.0)
        
        logger.info("Packet capture stopped")
    
    def get_statistics(self) -> dict:
        """
        Get capture statistics.
        
        Returns:
            Dictionary with capture statistics
        """
        duration = 0
        if self.start_time:
            duration = time.time() - self.start_time
        
        return {
            "is_capturing": self.is_capturing,
            "interface": self.interface,
            "filter": self.capture_filter,
            "packets_captured": self.packets_captured,
            "packets_processed": self.packets_processed,
            "duration_seconds": duration,
            "packets_per_second": self.packets_captured / max(1, duration),
            "queue_size": self.packet_queue.qsize(),
        }
    
    def test_capture(self, count: int = 10) -> list[ParsedPacket]:
        """
        Test capture by capturing a specified number of packets synchronously.
        
        This is useful for testing and debugging without starting the
        full background capture.
        
        Args:
            count: Number of packets to capture
            
        Returns:
            List of parsed packets
        """
        logger.info(f"Testing capture with {count} packets...")
        
        packets = []
        
        def test_handler(raw_packet: Packet):
            parsed = parser.parse_packet(raw_packet)
            if parsed:
                packets.append(parsed)
        
        try:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=test_handler,
                count=count,
                store=False,
            )
            logger.info(f"Captured {len(packets)} packets")
            return packets
        except Exception as e:
            logger.error(f"Test capture failed: {e}")
            return packets


def create_capture(
    interface: Optional[str] = None,
    capture_filter: str = "tcp or udp",
    packet_callback: Optional[Callable[[ParsedPacket], None]] = None,
) -> PacketCapture:
    """
    Factory function to create a PacketCapture instance.
    
    Args:
        interface: Network interface name
        capture_filter: BPF filter string
        packet_callback: Callback for each parsed packet
        
    Returns:
        Configured PacketCapture instance
    """
    return PacketCapture(
        interface=interface,
        capture_filter=capture_filter,
        packet_callback=packet_callback,
    )
