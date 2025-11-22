/* *****************************************************************************
* FILENAME:    capture_packet.h
 * DESCRIPTION: Header file supporting an ethernet connection to the HeIMDALL Data Acquistion (DAQ) Firmware
                In-Phase / Quadrature (IQ) server to recieve IQ packets.
 * AUTHOR:      Bertus Austin Shelters
 * DATE:        October 21, 2025
 * License:     GNU GPL V3
 * Disclaimer:  This program is free software: you can redistribute and/or modify it under the terms of the GNU Public
                License as published by the Free Software Foundation, either version 3 of the License, or an later version.
                You should have received a copy of the GNU General Public License along with this program. If not,see
                <https://www.gnu.org/licenses/.>. This program is distributed in the hope that it will be useful, but
                WITHOUT ANY WARRANTY; without even the implied waranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
                See the GNU General Public License for more details.
 * MODIFICATION:
 *   DATE        AUTHOR      CHANGES
 *   ----------  ----------  --------------------------------------------------
 *   2025-10-21  Bertus Shelters    Initial creation of the file.
 ***************************************************************************** */

#ifndef SHELTERS_SDR_TEST_IQ_CLIENT_H
#define SHELTERS_SDR_TEST_IQ_CLIENT_H
#endif //SHELTERS_SDR_TEST_IQ_CLIENT_H

// Standard Library or System-Level Headers
// Posix operating system API
#include <unistd.h>
//  Standard POSIX header used for network programming
#include <arpa/inet.h>

// User-defined header files
#include "log.h"


// The IQ Server is at port 5000
#define IQ_SERVER_PORT    5000
// Define the size of the ring buffer - 2 is set to create Ping Pong buffer
#define RING_BUFFER_SIZE 2

extern std::array<std::mutex, RING_BUFFER_SIZE> ringBufferMutex;
extern std::condition_variable startProcessing;
extern std::mutex startProcessingMutex;

/* *****************************************************************************
getPacketTypeStr: Returns the packet type string for the frame_type header field.
    Input: iqServerIPAddress (std::string) String representing the IPv4 address
    Ouput: socketfd: File Descriptor for IQ Packet Server Socket
***************************************************************************** */
std::string getPacketTypeStr(int frame_type)
{
    std::string frameTypeStr;
    switch (frame_type)
    {
    case 0:
        frameTypeStr = "Data";
        break;
    case 1:
        frameTypeStr = "Dummy";
        break;
    case 2:
        frameTypeStr = "Ramp";
        break;
    case 3:
        frameTypeStr = "Cal";
        break;
    case 4:
        frameTypeStr = "TrigW";
        break;
    default:
        frameTypeStr = "N/A";
        break;
    }
    return frameTypeStr;
}

/* *****************************************************************************
connectToIQServer: Open connection to the IQ Packet Server
    Input: iqServerIPAddress (std::string) String representing the IPv4 address
    Ouput: socketfd: File Descriptor for IQ Packet Server Socket
***************************************************************************** */
int connectToIQServer(std::string iqServerIPAddress)
{
    // Create a TCP socket in the IPV4 communications domain, and return a file descriptor
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0)
    {
        log_fatal("Failed to create socket");
        return (-1);
    }
    // Set the socket timeout to be 3 seconds (Handles the case where the DAQ server disconnects
    struct timeval tv;
    tv.tv_sec = 5; // 5 second timeout
    tv.tv_usec = 0; // 0 microseconds
    setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    //  Define the  IPv4 Internet domain socket address.
    struct sockaddr_in iqServerAddress;
    // Set address type IPv4
    iqServerAddress.sin_family = AF_INET;
    // Set the port number
    iqServerAddress.sin_port = (in_port_t)htons(IQ_SERVER_PORT);
    // Set the IP address of the socket
    iqServerAddress.sin_addr.s_addr = inet_addr(iqServerIPAddress.c_str());
    // Establish a connection to address on client_socket
    log_info("Attempting to connect to DAQ server at IP Address %s", iqServerIPAddress.c_str());
    int checkConnect = connect(socketfd, (struct sockaddr*)&iqServerAddress, sizeof(iqServerAddress));
    if (checkConnect < 0)
    {
        log_fatal("Failed to connect to DAQ server at IP Address %s", iqServerIPAddress.c_str());
        return (-1);
    }
    else
    {
        log_info("Connected to DAQ server at IP Address %s", iqServerIPAddress.c_str());
    }
    // Return the file descriptor of the socket
    return (socketfd);
}
