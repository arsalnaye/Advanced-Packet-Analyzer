#include <iostream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <string>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"

using namespace PacketAnalyzer;
using namespace DPI;


// ============================================================================
// Application-level protocol detection
// ============================================================================

void printApplicationInfo(const ParsedPacket& pkt) {

    if (pkt.payload_length == 0 || pkt.payload_data == nullptr) {
        return;
    }

    const uint8_t* payload = pkt.payload_data;
    size_t length = pkt.payload_length;

    std::cout << "\n[Application]\n";


    // ------------------------------------------------------------------------
    // TLS / SNI
    // ------------------------------------------------------------------------

    if (pkt.has_tcp &&
        SNIExtractor::isTLSClientHello(payload, length)) {

        std::cout << "  Protocol: TLS\n";

        auto sni = SNIExtractor::extract(payload, length);

        if (sni.has_value()) {
            std::cout << "  SNI:      "
                      << sni.value()
                      << "\n";
        } else {
            std::cout << "  SNI:      Not found\n";
        }

        return;
    }


    // ------------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------------

    if (pkt.has_tcp &&
        HTTPHostExtractor::isHTTPRequest(payload, length)) {

        std::cout << "  Protocol: HTTP\n";

        auto host = HTTPHostExtractor::extract(payload, length);

        if (host.has_value()) {
            std::cout << "  Host:     "
                      << host.value()
                      << "\n";
        } else {
            std::cout << "  Host:     Not found\n";
        }

        // Detect HTTP method
        const char* methods[] = {
            "GET ",
            "POST ",
            "PUT ",
            "HEAD ",
            "DELETE ",
            "PATCH ",
            "OPTIONS "
        };

        for (const char* method : methods) {

            size_t method_length =
                std::char_traits<char>::length(method);

            if (length >= method_length &&
                std::equal(
                    method,
                    method + method_length,
                    reinterpret_cast<const char*>(payload))) {

                std::string method_name(method);

                if (!method_name.empty() &&
                    method_name.back() == ' ') {

                    method_name.pop_back();
                }

                std::cout << "  Method:   "
                          << method_name
                          << "\n";

                break;
            }
        }

        return;
    }


    // ------------------------------------------------------------------------
    // DNS
    // ------------------------------------------------------------------------

    if (pkt.has_udp &&
        (pkt.src_port == 53 || pkt.dest_port == 53) &&
        DNSExtractor::isDNSQuery(payload, length)) {

        std::cout << "  Protocol: DNS\n";

        auto domain =
            DNSExtractor::extractQuery(payload, length);

        if (domain.has_value()) {
            std::cout << "  Query:    "
                      << domain.value()
                      << "\n";
        } else {
            std::cout << "  Query:    Not found\n";
        }

        return;
    }


    // ------------------------------------------------------------------------
    // Unknown
    // ------------------------------------------------------------------------

    std::cout << "  Protocol: Unknown\n";
}


// ============================================================================
// Packet summary
// ============================================================================

void printPacketSummary(
    const ParsedPacket& pkt,
    int packet_num
) {

    std::time_t time = pkt.timestamp_sec;
    std::tm* tm = std::localtime(&time);

    std::cout
        << "\n========== Packet #"
        << packet_num
        << " ==========\n";

    std::cout
        << "Time: "
        << std::put_time(tm, "%Y-%m-%d %H:%M:%S")
        << "."
        << std::setfill('0')
        << std::setw(6)
        << pkt.timestamp_usec
        << "\n";


    // ------------------------------------------------------------------------
    // Ethernet
    // ------------------------------------------------------------------------

    std::cout << "\n[Ethernet]\n";

    std::cout
        << "  Source MAC:      "
        << pkt.src_mac
        << "\n";

    std::cout
        << "  Destination MAC: "
        << pkt.dest_mac
        << "\n";

    std::cout
        << "  EtherType:       0x"
        << std::hex
        << std::setfill('0')
        << std::setw(4)
        << pkt.ether_type
        << std::dec;

    if (pkt.ether_type == EtherType::IPv4) {
        std::cout << " (IPv4)";
    }
    else if (pkt.ether_type == EtherType::IPv6) {
        std::cout << " (IPv6)";
    }
    else if (pkt.ether_type == EtherType::ARP) {
        std::cout << " (ARP)";
    }

    std::cout << "\n";


    // ------------------------------------------------------------------------
    // IP
    // ------------------------------------------------------------------------

    if (pkt.has_ip) {

        std::cout
            << "\n[IPv"
            << static_cast<int>(pkt.ip_version)
            << "]\n";

        std::cout
            << "  Source IP:      "
            << pkt.src_ip
            << "\n";

        std::cout
            << "  Destination IP: "
            << pkt.dest_ip
            << "\n";

        std::cout
            << "  Protocol:       "
            << PacketParser::protocolToString(pkt.protocol)
            << "\n";

        std::cout
            << "  TTL:            "
            << static_cast<int>(pkt.ttl)
            << "\n";
    }


    // ------------------------------------------------------------------------
    // TCP
    // ------------------------------------------------------------------------

    if (pkt.has_tcp) {

        std::cout << "\n[TCP]\n";

        std::cout
            << "  Source Port:      "
            << pkt.src_port
            << "\n";

        std::cout
            << "  Destination Port: "
            << pkt.dest_port
            << "\n";

        std::cout
            << "  Sequence Number:  "
            << pkt.seq_number
            << "\n";

        std::cout
            << "  Ack Number:       "
            << pkt.ack_number
            << "\n";

        std::cout
            << "  Flags:            "
            << PacketParser::tcpFlagsToString(pkt.tcp_flags)
            << "\n";
    }


    // ------------------------------------------------------------------------
    // UDP
    // ------------------------------------------------------------------------

    if (pkt.has_udp) {

        std::cout << "\n[UDP]\n";

        std::cout
            << "  Source Port:      "
            << pkt.src_port
            << "\n";

        std::cout
            << "  Destination Port: "
            << pkt.dest_port
            << "\n";
    }


    // ------------------------------------------------------------------------
    // Payload
    // ------------------------------------------------------------------------

    if (pkt.payload_length > 0 &&
        pkt.payload_data != nullptr) {

        std::cout << "\n[Payload]\n";

        std::cout
            << "  Length: "
            << pkt.payload_length
            << " bytes\n";

        std::cout << "  Preview: ";

        size_t preview_len =
            std::min(
                pkt.payload_length,
                static_cast<size_t>(32)
            );

        for (size_t i = 0;
             i < preview_len;
             i++) {

            std::cout
                << std::hex
                << std::setfill('0')
                << std::setw(2)
                << static_cast<int>(pkt.payload_data[i])
                << " ";
        }

        if (pkt.payload_length > 32) {
            std::cout << "...";
        }

        std::cout << std::dec << "\n";

        // Application-level analysis
        printApplicationInfo(pkt);
    }
}


// ============================================================================
// Usage
// ============================================================================

void printUsage(const char* program_name) {

    std::cout
        << "Usage: "
        << program_name
        << " <pcap_file> [max_packets]\n";

    std::cout << "\nArguments:\n";

    std::cout
        << "  pcap_file   - Path to a .pcap file captured by Wireshark\n";

    std::cout
        << "  max_packets - (Optional) Maximum number of packets to display\n";

    std::cout << "\nExample:\n";

    std::cout
        << "  "
        << program_name
        << " capture.pcap\n";

    std::cout
        << "  "
        << program_name
        << " capture.pcap 10\n";
}


// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {

    std::cout
        << "====================================\n"
        << "     Packet Analyzer v1.1\n"
        << "====================================\n\n";


    // ------------------------------------------------------------------------
    // Arguments
    // ------------------------------------------------------------------------

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string filename = argv[1];

    int max_packets = -1;

    if (argc >= 3) {

        try {
            max_packets = std::stoi(argv[2]);
        }
        catch (const std::exception&) {

            std::cerr
                << "Error: max_packets must be an integer.\n";

            return 1;
        }
    }


    // ------------------------------------------------------------------------
    // Open PCAP
    // ------------------------------------------------------------------------

    PcapReader reader;

    if (!reader.open(filename)) {
        return 1;
    }

    std::cout
        << "\n--- Reading packets ---\n";


    // ------------------------------------------------------------------------
    // Read packets
    // ------------------------------------------------------------------------

    RawPacket raw_packet;
    ParsedPacket parsed_packet;

    int packet_count = 0;
    int parse_errors = 0;

    while (reader.readNextPacket(raw_packet)) {

        packet_count++;

        if (PacketParser::parse(
                raw_packet,
                parsed_packet)) {

            printPacketSummary(
                parsed_packet,
                packet_count
            );
        }
        else {

            std::cerr
                << "Warning: Failed to parse packet #"
                << packet_count
                << "\n";

            parse_errors++;
        }

        if (max_packets > 0 &&
            packet_count >= max_packets) {

            std::cout
                << "\n(Stopped after "
                << max_packets
                << " packets)\n";

            break;
        }
    }


    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------

    std::cout
        << "\n====================================\n"
        << "Summary:\n"
        << "  Total packets read:  "
        << packet_count
        << "\n"
        << "  Parse errors:        "
        << parse_errors
        << "\n"
        << "====================================\n";


    reader.close();

    return 0;
}