/* *****************************************************************************
 * FILENAME:    krakenrf_sigmf.cpp
 * DESCRIPTION: This program establishes an ethernet connection to the HeIMDALL Data Acquistion (DAQ) Firmware
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

// Standard Library or System-Level Headers
// c++ standard library header for handling arrays
#include <array>
// c++ standard library header for atomic operations
#include <atomic>
// c++ standard library header for condition variables
#include <condition_variable>
// c++ standard library header for file system operations and their components
#include <filesystem>
// c++ standard library header for mutex
#include <mutex>
// c++ standard library header for threads
#include <thread>
// getopt.h is a header file in C and C++ programming that provides functions for parsing command-line arguments. It is part of the GNU C Library (glibc)
#include <getopt.h>

// User-defined header files
#include "ring_buffer.h"
#include "capture_packet.h"
#include "process_iq_packet.h"

// Ratio of bytes to bits
#define BYTES_2_BITS 8 // bytes/bits
// Calibration status error value
#define CALIBRATION_STATUS -1
// Capture process error value
#define CAPTURE_ERROR -2
// Input argument error value
# define ARGUMENT_ERROR -4

typedef struct option Option;

/* *****************************************************************************
Global program control variables
***************************************************************************** */
// Initalize the ringBufferPtr struct as a global variable to be passed between the write and read functions
struct ringBufferPtr* ringBufPtr;
// Create mutex for the ping and pong buffer
std::array<std::mutex, RING_BUFFER_SIZE> ringBufferMutex;
// Create a condition variable to synchronize capture and processing threads
std::condition_variable startProcessing;
// Create a mutex lock for the condition variable
std::mutex startProcessingMutex;
// Create a atomic boolean to turn off the processing thread when the capture thread completes
std::atomic<bool> captureOn = true;
// Create a atomic boolean to turn off the processing thread upon error in the capture thread
std::atomic<bool> endProcessingThread = true;
// Create a atomic boolean to turn off the capture thread upon error in the processing thread
std::atomic<bool> endCaptureThread = true;
// Count of the number of packets to process
int packetProcessed = 0;
// Error value to be returned if there is an error
int errorValue = 0;

/* *****************************************************************************
Create the threads for multithreading
***************************************************************************** */
// Thread 0 Routine - Capture IQ Packets
void threadCaptureRoutine(int requestedPackets, std::string iqServerIPAddress)
{
    log_info("Starting Capture Thread");
    // Allocate a buffer to store the iqHeader struct for the process thread
    struct iq_header_struct* captureHeaderPtr = (struct iq_header_struct*)calloc(1, sizeof(struct iq_header_struct));
    // Connect to the socket
    int socketfd = connectToIQServer(iqServerIPAddress);
    // If connectToIQServer Fails, exit the program
    if (socketfd < 0)
    {
        log_error("Failed to create socket");
        // Signal the processing thread to stop
        captureOn = false;
        endProcessingThread = false;
        // Signal processing thread to start so it can stop
        std::lock_guard<std::mutex> lk(startProcessingMutex);
        startProcessing.notify_all();
        // Garbage collect
        captureHeaderPtr = nullptr;
        free(captureHeaderPtr);
        // Set the error report flag
        errorValue = CAPTURE_ERROR;
        // Exit the capture thread
        log_info("Ending Capture Thread");
        return;
    }
    // Create the message to the IQ server to start streaming
    char command[] = "streaming";
    // Create the message to the IQ server to keep streaming
    char newpacketcommand[] = "IQDownload";
    // Send the message to start IQ packet streaming
    int checksend = send(socketfd, command, strlen(command), 0);
    // Make sure that the message was sent
    if (checksend < 0)
    {
        log_error("Failed to send streaming command");
        // Signal the processing thread to stop
        captureOn = false;
        endProcessingThread = false;
        // Signal processing thread to start so it can stop
        std::lock_guard<std::mutex> lk(startProcessingMutex);
        startProcessing.notify_all();
        // Garbage collect
        captureHeaderPtr = nullptr;
        free(captureHeaderPtr);
        // Set the error report flag
        errorValue = CAPTURE_ERROR;
        // Exit the capture thread
        log_info("Ending Capture Thread");
        return;
    }
    else
    {
        log_info("Sent streaming command to DAQ");
    }
    // Initalize packet read loop control variables
    // Counter for the number of bytes successfully read for the current packet
    int byteCounter;
    // Number of bytes read in call to recv()
    int currentBytesRead;
    // Start the processing loop
    for (int packetCounter = 0; packetCounter < requestedPackets; packetCounter++)
    {
        // Check to see if the processing thread has signaled a shutdown
        if (!endCaptureThread)
        {
            // If signaled, end capture thread
            // Garbage collect
            captureHeaderPtr = nullptr;
            free(captureHeaderPtr);
            // Set the error report flag
            errorValue = CAPTURE_ERROR;
            // Exit the capture thread
            log_info("Ending Capture Thread");
            return;
        }
        // Counter for the number of bytes successfully read for the current packet
        byteCounter = 0;
        // Get the ring buffer index and pointer to read
        struct updateRingBufferPtr updateRingBufPtr = writeRingBuffer(ringBufPtr);
        // Acquire the ring buffer mutex for the packet index requested
        ringBufferMutex[updateRingBufPtr.packetIndex].lock();
        log_trace("Capture Thread Mutex Lock: Buffer %d", updateRingBufPtr.packetIndex);
        log_info("Start Writing Capture Packet %d to Buffer %d", packetCounter, updateRingBufPtr.packetIndex);
        // Number of bytes read in call to recv()
        currentBytesRead = 0;
        // First pull the header from the packet
        currentBytesRead = recv(socketfd, (updateRingBufPtr.bufferStartPointer), HEADER_SIZE,MSG_WAITALL);
        if (currentBytesRead > 0)
        {
            log_debug("Capture packet %d header read %d bytes out of %d bytes", packetCounter, currentBytesRead,
                      HEADER_SIZE);
            byteCounter += currentBytesRead;
        }
        if (currentBytesRead == -1)
        {
            log_error("Failed to capture packet %d header. Terminating. ", packetCounter);
            // Signal the processing thread to stop
            captureOn = false;
            endProcessingThread = false;
            // Signal processing thread to start so it can stop
            std::lock_guard<std::mutex> lk(startProcessingMutex);
            startProcessing.notify_all();
            // Set the error report flag
            errorValue = CAPTURE_ERROR;
            // Garbage collect
            captureHeaderPtr = nullptr;
            free(captureHeaderPtr);
            // Exit the capture thread
            log_info("Ending Capture Thread");
            return;
        }
        // Get the header fields from the packet
        getHeaderFields(updateRingBufPtr.bufferStartPointer, captureHeaderPtr);
        // Check if the packet is valid
        // Check 1: Ensure the header starts with the expected sync_word field
        // Check 2: Ensure the packet version is supported by the capture software
        bool validHeader = (checkSyncWord(captureHeaderPtr) && checkPacketVersion(captureHeaderPtr));
        if (!validHeader)
        {
            // If header is not valid report it to the log
            log_warn("Capture packet %d is not valid. (Processing thread will ignore packet)", packetCounter);
        }
        // Get the default packet size
        int packetSize = ringBufPtr->packetSize;
        int payloadSize = packetSize - HEADER_SIZE;
        // Check if a valid packet is a data packet. Since Cal type packets have a different CPI size than data types, the CPI size should be updated if the packet is not a data type.
        // If the packet type is not Data, we still read it in order to keep the IQ server from stalling.
        if (validHeader && (captureHeaderPtr->frame_type != 0))
        {
            log_warn("Capture packet %d is %s type. (Processing thread will ignore packet).", packetCounter,
                     getPacketTypeStr(captureHeaderPtr->frame_type).c_str());
            // Get the packet size of the packet to be read
            payloadSize = ((captureHeaderPtr->cpi_length * 2 * captureHeaderPtr->active_ant_chs * captureHeaderPtr->
                sample_bit_depth) / BYTES_2_BITS);
            packetSize = payloadSize + HEADER_SIZE;
        }
        // Read in an individual packet with repeated calls to recv() until all of the bytes of the packet are recieved
        while (byteCounter < packetSize)
        {
            // Read the data from the IQ server
            currentBytesRead = recv(socketfd, (byteCounter + updateRingBufPtr.bufferStartPointer),
                                    (packetSize - byteCounter),MSG_WAITALL);
            // Update the number of bytes count (Note recv() returns -1 if the TCP transfer fails)
            if (currentBytesRead > 0)
            {
                byteCounter += currentBytesRead;
                log_debug("Packet %d: Successfully captured packet payload %d bytes out of %d bytes", packetCounter,
                          currentBytesRead, payloadSize);
            }
            if (currentBytesRead == -1)
            {
                log_error("Packet %d: Failed to receive TCP packet from DAQ", packetCounter);
                // Signal the processing thread to stop
                captureOn = false;
                endProcessingThread = false;
                // Signal processing thread to start so it can stop
                std::lock_guard<std::mutex> lk(startProcessingMutex);
                startProcessing.notify_all();
                // Set the error report flag
                errorValue = CAPTURE_ERROR;
                // Garbage collect
                captureHeaderPtr = nullptr;
                free(captureHeaderPtr);
                // Exit the capture thread
                log_info("Ending Capture Thread");
                return;
            }
        }
        // Send command to keep streaming
        checksend = send(socketfd, newpacketcommand, strlen(newpacketcommand), 0);
        // Make sure that the message was sent
        if (checksend < 0)
        {
            log_error("Failed to send IQDownload command");
            // Signal the processing thread to stop
            captureOn = false;
            endProcessingThread = false;
            // Signal processing thread to start so it can stop
            std::lock_guard<std::mutex> lk(startProcessingMutex);
            startProcessing.notify_all();
            // Set the error report flag
            errorValue = CAPTURE_ERROR;
            // Garbage collect
            captureHeaderPtr = nullptr;
            free(captureHeaderPtr);
            // Exit the capture thread
            log_info("Ending Capture Thread");
            return;
        }
        else
        {
            log_debug("Sent IQDownload command to DAQ");
        }
        log_info("Stop Writing Capture Packet %d to Buffer %d", packetCounter, updateRingBufPtr.packetIndex);
        // Release the mutex
        ringBufferMutex[updateRingBufPtr.packetIndex].unlock();
        log_trace("Capture Thread Mutex UnLock: Buffer %d", updateRingBufPtr.packetIndex);
        // Signal processing thread to start so it can stop
        std::lock_guard<std::mutex> lk(startProcessingMutex);
        startProcessing.notify_all();
    }
    // Close the socket
    close(socketfd);
    log_info("Closing connection to DAQ server at IP Address %s", iqServerIPAddress.c_str());
    //int checkError = getPackets(ringBufPtr, requestedPackets, iqServerIPAddress);
    // Once all the packets are read close the processing thread
    captureOn = false;
    // Garbage collect
    captureHeaderPtr = nullptr;
    free(captureHeaderPtr);
    log_info("Ending Capture Thread");
}

// Thread 1 Routine - Process IQ Packets
void threadProcessRoutine(std::string directory)
{
    log_info("Starting Processing Thread");
    // Allocate a buffer to store the iqHeader struct for the process thread
    struct iq_header_struct* processHeaderPtr = (struct iq_header_struct*)calloc(1, sizeof(struct iq_header_struct));
    while (captureOn)
    {
        // Create a readbuffer control struct
        struct updateRingBufferPtr updateRingBufPtr = readRingBuffer(ringBufPtr);
        // Wait for signal from the capture thread
        std::unique_lock<std::mutex> lk(startProcessingMutex);
        startProcessing.wait(lk);
        // Make sure the capture thread did not call to shutdown
        if (!endProcessingThread)
        {
            // Garbage collect
            processHeaderPtr = nullptr;
            free(processHeaderPtr);
            log_info("Ending Processing Thread");
            return;
        }
        // Acquire the ring buffer mutex for the packet index requested
        log_trace("Processing Thread Mutex Lock: Buffer %d", updateRingBufPtr.packetIndex);
        ringBufferMutex[updateRingBufPtr.packetIndex].lock();
        // Populate the header struct
        getHeaderFields(updateRingBufPtr.bufferStartPointer, processHeaderPtr);
        // Check if the packet is valid prior to starting processing (Drop if not valid)
        // Check 1: Ensure the header starts with the expected sync_word field
        // Check 2: Ensure the packet version is supported by the capture software
        bool validPacket = (checkSyncWord(processHeaderPtr) && checkPacketVersion(processHeaderPtr));
        // Check if the packet is a valid data packet (vs Calibration or Dummy frame)
        bool isDataFrame = (processHeaderPtr->frame_type == 0);
        // if the packet is valid and is in fact a data packet, write a SigMF file
        if (validPacket && isDataFrame)
        {
            log_info("Start Reading Processing Packet %d from Buffer %d", packetProcessed,
                     updateRingBufPtr.packetIndex);
            int checkError = makeSigMF(updateRingBufPtr.bufferStartPointer, processHeaderPtr, directory);
            // Check to see if the makeSigMF function had an error or not.
            if (checkError < 0)
            {
                // If an error is found, close the thread
                // Signal the capture thread to shut down
                endCaptureThread = false;
                // Garbage collect
                processHeaderPtr = nullptr;
                free(processHeaderPtr);
                // Set the error report flag
                errorValue = FILE_PROCESSING_ERROR;
                log_info("Ending Processing Thread");
                return;
            }
            log_info("Stop Reading Processing Packet %d from Buffer %d", packetProcessed, updateRingBufPtr.packetIndex);
            packetProcessed++;
        }
        else
        {
            // Warn if packet is dropped
            //Get the frame string
            log_warn(" Packet %d Dropped from Buffer %d. Frame Type is %s, Packet Valid?: %b.", packetProcessed,
                     updateRingBufPtr.packetIndex, getPacketTypeStr(processHeaderPtr->frame_type).c_str(), validPacket);
        }
        // Release the mutex
        ringBufferMutex[updateRingBufPtr.packetIndex].unlock();
        log_trace("Processing Thread Mutex Unlock: Buffer %d", updateRingBufPtr.packetIndex);
    }
    // Garbage collect
    processHeaderPtr = nullptr;
    free(processHeaderPtr);
    log_info("Ending Processing Thread");
}

/* *****************************************************************************
Main Processing Loop
***************************************************************************** */
int main(int argc, char* argv[])
{
    /* *****************************************************************************
    Set input parameters to default values
    ***************************************************************************** */
    // IP address of the server (Default to the loop back IP address (127.0.0.1) (Command line option --ip-address)
    std::string iqServerIPAddress = "127.0.0.1";
    // Number of packets to be read (Default to 1 packet)  (Command line option --count)
    int requestedPackets = 1;
    // Directory to write to ( Default is the current working directory) (Command line option --directory)
    std::string directory = std::filesystem::current_path();
    // Output log info to console control (Default to 1 (quiet mode)) ( Command line option --verbose)
    int consoleOutput = 1;
    log_set_quiet(consoleOutput);
    // Set the default log level - default is to log only on fatal errors, (command line option --debug)
    int logLevel = LOG_FATAL;
    // Determine if a log file is created default is to not create a lg file (command line option --debug)
    bool makeLogFile = false;
    /* *****************************************************************************
    Handle Inputs
    ***************************************************************************** */
    // Option character input read
    int optionCharacter = 0;
    // Define the optional inputs to the program
    static Option long_options[] = {
        {"ip-address", required_argument, NULL, 'i'},
        {"count", required_argument, NULL, 'c'},
        {"directory", required_argument, NULL, 'd'},
        {"debug", no_argument, NULL, 'e'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'r'},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;
    while ((optionCharacter = getopt_long(argc, argv, "i:c:d:evh", long_options, &option_index)) != -1)
    {
        switch (optionCharacter)
        {
        case 'i':
            iqServerIPAddress = optarg;
            break;
        case 'c':
            requestedPackets = atoi(optarg);
            break;
        case 'd':
            directory = optarg;
            break;
        case 'e':
            // If debug mode is selected change log level to the lowest level
            logLevel = LOG_TRACE;
            // Create a log file
            makeLogFile = true;
            break;
        case 'v':
            // If debug mode is select the "info" log level
            logLevel = LOG_INFO;
            // Print log information to the console
            consoleOutput = 0;
            break;
        case 'h':
            printf(
                "\nKrakenSDR SigMF Writer Version 1.0"
                "\nPurpose: Connect to a KrakenSDR Data Acquisition (DAQ) IQ server at a specified IP address to capture and store IQ packets as SigMF formated files."
                " \n Program Arguments:"
                "\n\t-> --ip-address  IPv4 address of the KrakenSDR DAQ Server."
                "\n\t-> --count number of IQ packets to read."
                "\n\t-> --directory filepath to directory to save SigMF files."
                "\n\t-> --debug (no argument) produce IQCaptureLog.txt log file in current directory for debugging."
                "\n\t-> --help (no argument) prints program purpose, arguments, and return values."
                "\n\t-> --verbose (no argument) print information about program progress to console."
                "\n\t-> --version (no argument) prints the version number and license information."
                "\nReturn Value (RV):"
                "\n\t RV >= 0 Give the number of packets successfully written to SigMF. (*See note below)"
                "\n\t RV = -1 Program exited since DAQ is in calibration mode. Wait till the DAQ finishes calibration and try again."
                "\n\t RV = -2 Program exited due to error in Capture Thread. Run --debug for troubleshooting."
                "\n\t RV = -3 Program exited due to error in Processing Thread. Run --debug for troubleshooting."
                "\n\t RV = -4 Program exited due to invalid input arguments. Check input arguments."
                "\n *Note: The number of packets written may be less than the number requested due to calibration or data transfer errors."
                "\nReport bugs to: b.shelters.5@gmail.com"
                "\npkg home page: <https://github.com/bshelters/KrakenSigMFWriter>."
                "\n");
            return 0;
        case 'r':
            printf(
                "\nKrakenSDR SigMFWriter 1.0"
                "\nCopyright (C) 2007 Free Software Foundation, Inc."
                "\nLicense GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>"
                "\nThis is free software: you are free to change and redistribute it."
                "\nThere is NO WARRANTY, to the extent permitted by law."
                "\nAuthor: Bertus Austin Shelters, b.shelters.5@gmail.com."
                "\n");
            return 0;
        case '0':
            break;
        case '?':
            break;
        }
    }
    /* *****************************************************************************
    Start the logging file
    ***************************************************************************** */
    // Enable log quiet mode (Log info is in text file vs the console)
    log_set_quiet(consoleOutput);
    if (makeLogFile)
    {
        // Create a log file
        FILE* logFptr = fopen("IQPacketCaptureLog.txt", "w");
        // Handle error
        if (logFptr == NULL)
        {
            fprintf(stderr, "Failed to create a log file \n");
        }
        // Set the file pointer for the log file
        log_set_fp(logFptr);
    }
    // Set the log level
    log_set_level(logLevel);
    // Log the header version and SigMF specification version
    log_info("Starting Kraken SDR SigMF File Writer");
    log_info("Writer configured for Kraken SDR IQ packet header version: %d", HEADER_VERSION);
    log_info("Writer configured for SigMF specification version: %s", SIGMF_SPEC);
    /* *****************************************************************************
    // Make sure the input values are valid
    ***************************************************************************** */
    // Make sure the input IP address is valid
    if (inet_addr(iqServerIPAddress.c_str()) == (in_addr_t)(-1))
    {
        log_fatal("Argument for --iqServerIPAddress (IP Address of the DAQ Server) is not valid");
        return (ARGUMENT_ERROR);
    }
    // Make sure that the requested packets values are valid
    if (requestedPackets <= 0)
    {
        log_fatal("Argument for --count (Number of IQ packets to read) is not valid");
        return (ARGUMENT_ERROR);
    }
    // Make sure that the directory exists
    if (access(directory.c_str(), F_OK) != 0)
    {
        log_fatal("Argument for --directory (filepath to directory to save SigMF files) is not valid");
        return (ARGUMENT_ERROR);
    }
    /* *****************************************************************************
    Initialize the IQ Header Struct
    ***************************************************************************** */
    // Initalize the IQ header struct on the heap
    struct iq_header_struct* initHeaderPtr = (struct iq_header_struct*)calloc(1, sizeof(struct iq_header_struct));
    /* *****************************************************************************
    Get the initialization packet which is just the first packet
    ***************************************************************************** */
    // Create a buffer to read into
    size_t headerSize = HEADER_SIZE;
    int* headerReadBuffer = (int*)calloc(sizeof(uint32_t), (headerSize) / sizeof(uint32_t));
    int socketfd;
    // Try to connect to the IQ server
    // Connect to the socket
    socketfd = connectToIQServer(iqServerIPAddress);
    // If connectToIQServer Fails, exit the program
    if (socketfd < 0)
    {
        return (CAPTURE_ERROR);
    }
    // Create the message to the IQ server to start streaming
    char command[] = "streaming";
    // Send the message to start IQ packet streaming
    int checksend = send(socketfd, command, strlen(command), 0);
    // Make sure that the message was sent
    if (checksend < 0)
    {
        log_error("Failed to send streaming command. Terminating.");
        return (CAPTURE_ERROR);
    }
    else
    {
        log_info("Sent streaming command to DAQ");
    }
    // Get the header bytes from the DAQ
    int bytesRead = recv(socketfd, headerReadBuffer, headerSize,MSG_WAITALL);
    if (bytesRead > 0)
    {
        log_debug("Reading initialization header: %d bytes out of %d bytes", bytesRead, headerSize);
    }
    if (bytesRead == -1)
    {
        log_error("Failed to read initialization packet header. Terminating.");
        return (CAPTURE_ERROR);
    }
    // Parse the header fields
    getHeaderFields(headerReadBuffer, initHeaderPtr);
    // Check if the packet is valid (if not try again)
    // Check 1: Ensure the header starts with the expected sync_word field
    // Check 2: Ensure the packet version is supported by the capture software
    bool validHeader = (checkSyncWord(initHeaderPtr) && checkPacketVersion(initHeaderPtr));
    if (!validHeader)
    {
        // If header is not valid report header is not valid
        log_fatal("Failed to read valid initialization packet header. Terminating.");
        return (CAPTURE_ERROR);
    }
    // Check if the packet is a data type packet. Cal type packets have a different CPI size than data types.
    if (initHeaderPtr->frame_type != 0)
    {
        log_fatal("Initialization packet type is not data type frame (Calibration). Terminating.");
        return (CALIBRATION_STATUS);
    }
    log_info("Initialization packet parameters: CPI Length = %d, Number Active Channels = %d, Sample Bit Depth = %d",
             initHeaderPtr->cpi_length, initHeaderPtr->active_ant_chs, initHeaderPtr->sample_bit_depth);
    // Determine the payload size from the packet header
    int payloadSize = (initHeaderPtr->cpi_length * 2 * initHeaderPtr->active_ant_chs * initHeaderPtr->sample_bit_depth)
        / BYTES_2_BITS;
    // Create a buffer to store the first payload - needed to clear out the IQ server
    int* tempPayloadBuffer = (int*)calloc(1, payloadSize);
    // Counter for the number of bytes successfully read for the current packet
    int byteCounter = 0;
    int payloadBytesRead = 0;
    // Read in individual payload packet with repeated calls to recv() until all of the bytes of the packet are brought in
    while (byteCounter < payloadSize)
    {
        // Read the data from the IQ server
        payloadBytesRead = recv(socketfd, tempPayloadBuffer, (payloadSize - byteCounter),MSG_WAITALL);
        // Update the number of bytes count (Note recv() returns -1 if the TCP transfer fails)
        if (payloadBytesRead > 0)
        {
            byteCounter += payloadBytesRead;
            log_debug("Initialization Packet Payload: Successfully received %d bytes out of %d bytes", payloadBytesRead,
                      byteCounter);
        }
        if (payloadBytesRead == -1)
        {
            log_error("Initialization Packet Payload: Failed to receive TCP packet from DAQ for first Header");
            return (CAPTURE_ERROR);
        }
    }
    close(socketfd);
    // Close the socket
    log_info("Closing ethernet connection to DAQ server at IP Address %s", iqServerIPAddress.c_str());
    // Free up the heap space for
    headerReadBuffer = nullptr;
    free(headerReadBuffer);
    tempPayloadBuffer = nullptr;
    free(tempPayloadBuffer);
    initHeaderPtr = nullptr;
    free(initHeaderPtr);
    /* *****************************************************************************
    Initialize the Ping Pong Buffer (A ping pong buffer is a ring buffer of size 2)
    ***************************************************************************** */
    // Determine the packet size based on the CPI size, number of channels, and sample of bit depth ( Should not change) determined from the first packet
    int packetSize = HEADER_SIZE + payloadSize;
    // Update the capture ring buffer
    ringBufPtr = makeRingBuffer(RING_BUFFER_SIZE, packetSize);
    log_info("Creating Packet Capture Ring Buffer. Buffer Size = %d, Packet Size = %d bytes", RING_BUFFER_SIZE,
             packetSize);
    /* *****************************************************************************
    Set up multi-threading
    ***************************************************************************** */
    // Create the vector of the mutex for the ring buffer
    // Create the capture (read) thread
    std::thread captureThread(threadCaptureRoutine, requestedPackets, iqServerIPAddress);
    // Create the processing thread
    std::thread processingThread(threadProcessRoutine, directory);
    // Join threads at the end of execution
    captureThread.join();
    processingThread.join();
    log_info("Execution Complete: %d packets wrote to SigMF", packetProcessed);
    /* *****************************************************************************
    Close Out Actions: Garbage Collection and close files
    ***************************************************************************** */
    // Close out the log file
    // Clean up the heap
    // Perform Garbage collection
    free(ringBufPtr->bufferStartPointer);
    ringBufPtr->bufferStartPointer = nullptr;
    free(ringBufPtr);
    ringBufPtr = nullptr;
    // Send the return value
    // Return the error value if there is an error
    if (errorValue < 0)
    {
        return errorValue
        ;
    }
    else
    {
        return packetProcessed;
    }
}
