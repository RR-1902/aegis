"""
Capture lifecycle manager for AEGIS.

This module manages the packet capture lifecycle including:
- Starting and stopping capture
- Managing capture state
- Providing statistics
- Handling errors and recovery
"""

import logging
from typing import Optional

from app.capture.packet_capture import PacketCapture, create_capture
from app.config.settings import settings

logger = logging.getLogger(__name__)


class CaptureManager:
    """
    Manages the packet capture lifecycle for the AEGIS system.
    
    This class provides a high-level interface for managing packet capture,
    including starting, stopping, and monitoring the capture process.
    """
    
    def __init__(self):
        """Initialize the capture manager."""
        self.capture: Optional[PacketCapture] = None
        self.is_running = False
    
    def start_capture(
        self,
        interface: Optional[str] = None,
        capture_filter: Optional[str] = None,
        packet_callback=None,
    ) -> bool:
        """
        Start packet capture.
        
        Args:
            interface: Network interface (uses default if None)
            capture_filter: BPF filter (uses default if None)
            packet_callback: Callback for each parsed packet
            
        Returns:
            True if capture started successfully
        """
        if self.is_running:
            logger.warning("Capture already running")
            return False
        
        try:
            self.capture = create_capture(
                interface=interface or settings.capture_interface,
                capture_filter=capture_filter or settings.capture_filter,
                packet_callback=packet_callback,
            )
            
            success = self.capture.start()
            if success:
                self.is_running = True
                logger.info("Capture manager started successfully")
            else:
                logger.error("Failed to start capture")
            
            return success
            
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            return False
    
    def stop_capture(self) -> None:
        """Stop packet capture."""
        if not self.is_running:
            return
        
        if self.capture:
            self.capture.stop()
        
        self.is_running = False
        logger.info("Capture manager stopped")
    
    def get_statistics(self) -> dict:
        """
        Get capture statistics.
        
        Returns:
            Dictionary with capture statistics
        """
        if self.capture:
            return self.capture.get_statistics()
        return {
            "is_capturing": False,
            "interface": None,
            "packets_captured": 0,
            "packets_processed": 0,
        }
    
    def test_capture(self, count: int = 10):
        """
        Test packet capture.
        
        Args:
            count: Number of packets to capture
            
        Returns:
            List of captured packets
        """
        if self.capture:
            return self.capture.test_capture(count)
        return []


# Global capture manager instance
capture_manager = CaptureManager()
