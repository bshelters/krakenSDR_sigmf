/* *****************************************************************************
* FILENAME:     ring_buffer.h
 * DESCRIPTION: Header file for creating a circular buffer to capture packets from the ethernet connection to the
                HeIMDALL Data Acquistion (DAQ) Firmware In-Phase / Quadrature (IQ) server to recieve IQ packets.
 * AUTHOR:      Bertus Austin Shelters
 * DATE:        October 28, 2025
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
 *   2025-10-28  Bertus Shelters    Initial creation of the file.
 ***************************************************************************** */

#ifndef SHELTERS_SDR_TEST_PACKET_RING_BUFFER_H
#define SHELTERS_SDR_TEST_PACKET_RING_BUFFER_H

#endif //SHELTERS_SDR_TEST_PACKET_RING_BUFFER_H
/* *****************************************************************************
Define the ring buffer pointer struct which controls the ring buffer
***************************************************************************** */
struct ringBufferPtr
{
    // Number of packets that are stored in the buffer
    int numberPackets;
    // Size of each packet in bytes
    int packetSize;
    // Pointer to the start of the buffer
    int* bufferStartPointer;
    // Index of the next buffer to write
    int bufferReadIndex;
    // Index of the next buffer to read
    int bufferWriteIndex;
};

/* *****************************************************************************
Define the ring buffer pointer update struct
***************************************************************************** */
struct updateRingBufferPtr
{
    // Return the packet index for the next item to be addressed
    int packetIndex;
    // Pointer to the memory address for the packet index indicated
    int* bufferStartPointer;
};

/* *****************************************************************************
makeRingBuffer(): Creates a ring buffer for IQ packet sized for the worst case defined as the highest possible ethernet
                data rate [Fastest packet flow in] and the longest allowable processing time set as preprocesor directives.
                [Slowest packet flow out].
    Input: numberPackets (int) Size of the ring buffer
           packetSize: (integer) Size of each packet in bytes
    Output:ringBufPtr: (pointer) Pointer to a ringBufferPtr object for a ring buffer for indexing the buffer.
***************************************************************************** */
struct ringBufferPtr* makeRingBuffer(int numberPackets, int packetSize)
{
    // Allocate the buffer memory spaced on the heap
    int* bufferStartPointer = (int*)calloc(numberPackets, packetSize);
    // initalize the ring buffer structure object
    // Create the ring buffer struct
    struct ringBufferPtr ringBuf;
    ringBuf.numberPackets = numberPackets;
    ringBuf.packetSize = packetSize;
    ringBuf.bufferStartPointer = bufferStartPointer;
    // set the read and write start index to zero
    ringBuf.bufferReadIndex = 0;
    ringBuf.bufferWriteIndex = 0;
    // Allocate the pointer object memory
    struct ringBufferPtr* ringBufPtr = (struct ringBufferPtr*)calloc(1, sizeof(struct ringBufferPtr));
    // Save the ring buffer struct to the memory address
    *ringBufPtr = ringBuf;
    return ringBufPtr;
}

/* *****************************************************************************
readRingBuffer(): Helper function to read a ring buffer. Returns the pointer to next address to read to.
    Input:packetSize: (pointer) Pointer to a ringBufferPtr object for a ring buffer for indexing the buffer.
    Output:ringBufPtr: (pointer) Pointer to a ring buffer address save a packet
***************************************************************************** */
struct updateRingBufferPtr readRingBuffer(struct ringBufferPtr* ringBufPtr)
{
    // Creat a struct to return the requested ring buffer index and memory pointer
    struct updateRingBufferPtr updateRingBuf;
    // Get the buffer index to read from
    updateRingBuf.packetIndex = ringBufPtr->bufferReadIndex;
    // Get the pointer to the buffer indexed above
    updateRingBuf.bufferStartPointer = ringBufPtr->bufferReadIndex + ringBufPtr->bufferStartPointer;
    // Update the read pointer
    ringBufPtr->bufferReadIndex++;
    // Handle ring buffer rap around
    if (ringBufPtr->bufferReadIndex == ringBufPtr->numberPackets)
    {
        ringBufPtr->bufferReadIndex = 0;
    }
    return updateRingBuf;
}

/* *****************************************************************************
writeRingBuffer(): Helper function to write a ring buffer. Returns the pointer to next address to write to.
    Input:packetSize: (pointer) Pointer to a ringBufferPtr object for a ring buffer for indexing the buffer.
    Output:ringBufPtr: (pointer) Pointer to a ring buffer address save a packet
***************************************************************************** */
struct updateRingBufferPtr writeRingBuffer(struct ringBufferPtr* ringBufPtr)
{
    // Creat a struct to return the requested ring buffer index and memory pointer
    struct updateRingBufferPtr updateRingBuf;
    // Get the buffer index to write to
    updateRingBuf.packetIndex = ringBufPtr->bufferWriteIndex;
    // Get the pointer to the buffer indexed above
    updateRingBuf.bufferStartPointer = ringBufPtr->bufferWriteIndex + ringBufPtr->bufferStartPointer;
    // Update the read pointer
    ringBufPtr->bufferWriteIndex++;
    // Handle ring buffer rap around
    if (ringBufPtr->bufferWriteIndex == ringBufPtr->numberPackets)
    {
        ringBufPtr->bufferWriteIndex = 0;
    }
    return updateRingBuf;
}
