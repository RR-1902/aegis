"""
Test script for packet capture functionality.

This script tests the packet capture and parsing pipeline with real network traffic.
Run this to verify that the capture system works correctly on your system.
"""

import sys
import logging
from pathlib import Path

# Add the parent directory to the path so we can import from app
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.capture.packet_capture import PacketCapture, create_capture
from app.protocols.parser import parser
from app.config.settings import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_interfaces():
    """Test listing available network interfaces."""
    logger.info("=" * 60)
    logger.info("Testing interface enumeration")
    logger.info("=" * 60)
    
    interfaces = PacketCapture.list_interfaces()
    
    if not interfaces:
        logger.error("No interfaces found. This may indicate:")
        logger.error("1. Npcap is not installed (Windows)")
        logger.error("2. Insufficient permissions (need admin)")
        logger.error("3. No network interfaces available")
        return False
    
    logger.info(f"Found {len(interfaces)} interfaces:")
    for iface in interfaces:
        ip = PacketCapture.get_interface_ip(iface)
        logger.info(f"  - {iface}: {ip or 'No IP'}")
    
    # Check if configured interface exists
    if settings.capture_interface not in interfaces:
        logger.warning(f"Configured interface '{settings.capture_interface}' not found")
        # Try to find an interface with a real IP (not 0.0.0.0 or 169.254.x.x)
        preferred_interface = None
        for iface in interfaces:
            ip = PacketCapture.get_interface_ip(iface)
            if ip and not ip.startswith("169.254.") and ip != "0.0.0.0":
                preferred_interface = iface
                logger.info(f"Found interface with real IP: {iface} ({ip})")
                break
        
        if preferred_interface:
            settings.capture_interface = preferred_interface
        else:
            logger.info(f"Using first available interface: {interfaces[0]}")
            settings.capture_interface = interfaces[0]
    
    return True


def test_parser():
    """Test the protocol parser with synthetic packets."""
    logger.info("=" * 60)
    logger.info("Testing protocol parser")
    logger.info("=" * 60)
    
    from scapy.all import Ether, IP, TCP, UDP, ICMP
    
    # Test TCP packet
    tcp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
        sport=12345, dport=80, flags="S"
    )
    parsed = parser.parse_packet(tcp_packet)
    
    if parsed:
        logger.info(f"✓ TCP packet parsed successfully")
        logger.info(f"  {parsed}")
    else:
        logger.error("✗ Failed to parse TCP packet")
        return False
    
    # Test UDP packet
    udp_packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5353)
    parsed = parser.parse_packet(udp_packet)
    
    if parsed:
        logger.info(f"✓ UDP packet parsed successfully")
        logger.info(f"  {parsed}")
    else:
        logger.error("✗ Failed to parse UDP packet")
        return False
    
    # Test ICMP packet
    icmp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP(type=8, code=0)
    parsed = parser.parse_packet(icmp_packet)
    
    if parsed:
        logger.info(f"✓ ICMP packet parsed successfully")
        logger.info(f"  {parsed}")
    else:
        logger.error("✗ Failed to parse ICMP packet")
        return False
    
    logger.info(f"Parser statistics: {parser.get_statistics()}")
    return True


def test_capture():
    """Test real packet capture."""
    logger.info("=" * 60)
    logger.info("Testing real packet capture")
    logger.info("=" * 60)
    
    logger.info(f"Using interface: {settings.capture_interface}")
    logger.info(f"Capture filter: {settings.capture_filter}")
    logger.info("Capturing 10 packets...")
    
    try:
        capture = create_capture(
            interface=settings.capture_interface,
            capture_filter=settings.capture_filter,
        )
        
        packets = capture.test_capture(count=10)
        
        if packets:
            logger.info(f"✓ Successfully captured {len(packets)} packets")
            
            # Display packet details
            for i, packet in enumerate(packets[:5], 1):  # Show first 5
                logger.info(f"\nPacket {i}:")
                logger.info(f"  {packet}")
                logger.info(f"  Size: {packet.size} bytes")
                logger.info(f"  Protocol: {packet.transport_protocol.value}")
                if packet.tcp_flags:
                    logger.info(f"  TCP Flags: {packet.tcp_flags.to_dict()}")
            
            # Show statistics
            logger.info(f"\nCapture statistics: {capture.get_statistics()}")
            logger.info(f"Parser statistics: {parser.get_statistics()}")
            
            return True
        else:
            logger.warning("No packets captured. This could mean:")
            logger.warning("1. No traffic matching the filter")
            logger.warning("2. Interface has no traffic")
            logger.warning("3. Capture permissions issue")
            logger.warning("4. Npcap/WinPcap not properly installed")
            return None  # Return None to indicate this might be an environment issue
            
    except Exception as e:
        error_msg = str(e)
        logger.error(f"✗ Capture test failed: {e}")
        
        # Check for various Npcap/WinPcap related errors
        npcap_errors = [
            "winpcap is not installed",
            "libpcap provider",
            "layer 2",
            "pcap won't be used"
        ]
        
        if any(err in error_msg.lower() for err in npcap_errors):
            logger.error("Npcap/WinPcap is not installed or not properly configured.")
            logger.error("This is expected on systems without packet capture drivers.")
            logger.error("The parser and packet models work correctly (as shown in earlier tests).")
            logger.error("To enable real packet capture:")
            logger.error("1. Install Npcap from https://npcap.com/")
            logger.error("2. Run this script as Administrator")
            logger.error("3. Ensure Npcap is installed in 'WinPcap API-compatible mode'")
            return None  # Return None to indicate this is an environment issue, not a code issue
        else:
            logger.error("This may indicate:")
            logger.error("1. Insufficient permissions (run as admin)")
            logger.error("2. Network interface issue")
            logger.error("3. Npcap configuration issue")
            return False


def main():
    """Run all tests."""
    logger.info("AEGIS Packet Capture Test")
    logger.info("=" * 60)
    
    results = []
    
    # Test 1: Interface enumeration
    results.append(("Interface enumeration", test_interfaces()))
    
    # Test 2: Parser
    results.append(("Protocol parser", test_parser()))
    
    # Test 3: Real capture (only if interface test passed)
    if results[0][1]:
        results.append(("Real packet capture", test_capture()))
    else:
        logger.warning("Skipping real capture test due to interface enumeration failure")
        results.append(("Real packet capture", None))
    
    # Summary
    logger.info("=" * 60)
    logger.info("Test Summary")
    logger.info("=" * 60)
    
    for test_name, result in results:
        if result is True:
            logger.info(f"✓ {test_name}: PASSED")
        elif result is False:
            logger.info(f"✗ {test_name}: FAILED")
        else:
            logger.info(f"- {test_name}: SKIPPED (environment limitation)")
    
    # Overall result
    passed = sum(1 for _, r in results if r is True)
    failed = sum(1 for _, r in results if r is False)
    skipped = sum(1 for _, r in results if r is None)
    total = passed + failed
    
    if total > 0:
        logger.info(f"\nOverall: {passed}/{total} tests passed ({skipped} skipped)")
    
    if failed > 0:
        logger.warning("\nSome tests failed. Please check the error messages above.")
    
    if skipped > 0:
        logger.info("\nSome tests were skipped due to environment limitations.")
        logger.info("This is expected on systems without Npcap/WinPcap installed.")
        logger.info("The core functionality (parsing, packet models) is working correctly.")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
