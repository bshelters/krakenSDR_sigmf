//
// Created by bert on 10/28/25.
//

#ifndef SHELTERS_SDR_TEST_PROCESS_IQ_PACKET_H
#define SHELTERS_SDR_TEST_PROCESS_IQ_PACKET_H

#endif //SHELTERS_SDR_TEST_PROCESS_IQ_PACKET_H

// Standard Library or System-Level Headers
#include <openssl/evp.h>

#include "stringbuffer.h"
#include "prettywriter.h"


// Header size in bytes
#define HEADER_SIZE 1024
// The packet sync word in decimal
#define SYNC_WORD 737655130
// The capture software is designed for Header Version 7.
# define HEADER_VERSION 7
// Complex dataset format for the DAQ Firmware is Complex Float, 32 bit, Little Endian
# define DATASET_FORMAT "cf32_le"
// The version of the SigMF spec used
#define SIGMF_SPEC "1.2.5"
// Set the value for SIGMF file writing error
#define FILE_PROCESSING_ERROR -3

struct iq_header_struct
{
    uint32_t sync_word; //Updates: RTL-DAQ - Static
    uint32_t frame_type; //Updates: RTL-DAQ - Static
    char hardware_id[16]; //Updates: RTL-DAQ - Static
    uint32_t unit_id; //Updates: RTL-DAQ - Static
    uint32_t active_ant_chs; //Updates: RTL-DAQ - Static
    uint32_t ioo_type; //Updates: RTL-DAQ - Static
    uint64_t rf_center_freq; //Updates: RTL-DAQ - Static
    uint64_t adc_sampling_freq; //Updates: RTL-DAQ - Static
    uint64_t sampling_freq; //Updates: Decimator - Static
    uint32_t cpi_length; //Updates: Rebuffer / Decimator
    uint64_t time_stamp; //Updates: RTL-DAQ
    uint32_t daq_block_index; //Updates: RTL-DAQ
    uint32_t cpi_index; //Updates: Decimator
    uint64_t ext_integration_cntr; //Updates: RTL-DAQ
    uint32_t data_type; //Updates: Decimator - Static
    uint32_t sample_bit_depth; //Updates: RTL-DAQ->Decimator - Static
    uint32_t adc_overdrive_flags; //Updates: RTL-DAQ -> Rebuffer
    uint32_t if_gains[32]; //Updates: RTL-DAQ
    uint32_t delay_sync_flag; //Updates: Delay synchronizer
    uint32_t iq_sync_flag; //Updates: Delay synchronizer
    uint32_t sync_state; //Updates: Delay synchronizer
    uint32_t noise_source_state; //Updates: RTL-DAQ
    uint32_t reserved[192]; //Updates: RTL-DAQ - Static
    uint32_t header_version; //Updates: RTL-DAQ - Static
};

/* *****************************************************************************
convertUint32ToUint64t(): Combines binary data captured as two uint32_t and returns a single uint64_t.
    Input: lowerValue (int): First uint32_t big endian binary data o be placed in on the little endian side of the resulting uint64_t number
           upperValue (int): Second uint32_t big endian binary data to be placed in on the big endian side of the resulting uint64_t number
    Ouput: result (int): uint64_t value
***************************************************************************** */
uint64_t convertUint32ToUint64t(uint32_t lowerIndex, uint32_t upperIndex)
{
    // Move the upperIndex to the first position
    // First cast upper index value to a uint_64t
    uint64_t upperIndTemp = (uint64_t)(upperIndex);
    // Then shift the upper index value by 32 bits towards the Big Endian Side
    upperIndTemp = (upperIndTemp << 32);
    // Add in the lower index on the Little Endian Side
    // Cast the lower index value to a uint_64t
    uint64_t lowerIndTemp = (uint64_t)(lowerIndex);
    // Combine both parts to make the result
    return (upperIndTemp | lowerIndTemp);
}

/* *****************************************************************************
getHeaderFields(): Reads binary packet data and populates an IQ header packet at the specified address. Header version 7
                    is used (As of Nov 2025). Note that the byte addresses of each binary data might vary based on the
                    compiler settings used to to build the DAQ Firmware. In particular, there may differences in binary data
                    addresses due to differences in how alignment padding is done. See documentation.
    Input: bufferStartPtr (int*): Pointer to the start of an IQ packet in memory
           iqHeaderPtr: (int*) Pointer to the IQ header struct in memory
    Ouput: None
***************************************************************************** */
void getHeaderFields(int* bufferStartPtr, struct iq_header_struct* iqHeaderPtr)
{
    //Extract the header field values from the binary data in the ring buffer
    iqHeaderPtr->sync_word = bufferStartPtr[0];
    iqHeaderPtr->frame_type = bufferStartPtr[1];
    // Parse the hardware ID string which is sent as a character array
    // The data is read in 4 byte chunks, break up into individual bytes to access each character
    // Make a 32 bit mask equivalent to  0000000 0000000 0000000 11111111 in binary to pull one byte out at a time from a 32 bit binary number
    uint32_t bitMask32 = 255;
    uint32_t currentBitMask = 0;
    uint32_t currentFourByteValue = 0;
    uint32_t currentSingleByteValue = 0;
    int counter = 0;
    for (int i = 0; i < 4; i++)
    {
        // Get the 32 bit binary data for the hardware_id field
        currentFourByteValue = bufferStartPtr[2 + i];
        for (int j = 0; j < 4; j++)
        {
            currentSingleByteValue = 0;
            // Shift the bit mask to the appropiate position
            currentBitMask = bitMask32 << (8 * j);
            // Mask out the value using the bitwise "and" operator
            currentSingleByteValue = currentBitMask & currentFourByteValue;
            // Move the byte of interest to the "little end" to read out the integer value and cast to a char
            iqHeaderPtr->hardware_id[counter] = (char)(currentSingleByteValue >> (8 * j));
            // Update the byte index
            counter++;
        }
    }
    iqHeaderPtr->unit_id = bufferStartPtr[6];
    iqHeaderPtr->active_ant_chs = bufferStartPtr[7];
    iqHeaderPtr->ioo_type = bufferStartPtr[8];
    iqHeaderPtr->rf_center_freq = convertUint32ToUint64t(bufferStartPtr[10], bufferStartPtr[11]);
    iqHeaderPtr->adc_sampling_freq = convertUint32ToUint64t(bufferStartPtr[12], bufferStartPtr[13]);
    iqHeaderPtr->sampling_freq = convertUint32ToUint64t(bufferStartPtr[14], bufferStartPtr[15]);
    iqHeaderPtr->cpi_length = bufferStartPtr[16];
    iqHeaderPtr->time_stamp = convertUint32ToUint64t(bufferStartPtr[18], bufferStartPtr[19]);
    iqHeaderPtr->daq_block_index = bufferStartPtr[20];
    iqHeaderPtr->cpi_index = bufferStartPtr[21];
    iqHeaderPtr->ext_integration_cntr = convertUint32ToUint64t(bufferStartPtr[22], bufferStartPtr[23]);
    iqHeaderPtr->data_type = bufferStartPtr[24];
    iqHeaderPtr->sample_bit_depth = bufferStartPtr[25];
    iqHeaderPtr->adc_overdrive_flags = bufferStartPtr[26];
    for (int i = 0; i < 8; i++)
    {
        iqHeaderPtr->if_gains[i] = bufferStartPtr[27 + i];
    }
    iqHeaderPtr->delay_sync_flag = bufferStartPtr[59];
    iqHeaderPtr->iq_sync_flag = bufferStartPtr[60];
    iqHeaderPtr->sync_state = bufferStartPtr[61];
    iqHeaderPtr->noise_source_state = bufferStartPtr[62];
    iqHeaderPtr->header_version = bufferStartPtr[255];
}

/* *****************************************************************************
checkSyncWord(): Verifies that a packet contains the sync_word at the start of a header file
    Input:  iqHeaderPtr: (int*) Pointer to the IQ header struct in memory
    Ouput:  result (Bool): True if the sync_word is placed at the correct index
***************************************************************************** */
bool checkSyncWord(struct iq_header_struct* iqHeaderPtr)
{
    // Get the pointer to start of the ring buffer location
    bool result = false;
    // Check the packet sync word at byte address zero
    if (iqHeaderPtr->sync_word == SYNC_WORD)
    {
        result = true;
    }
    return result;
}

/* *****************************************************************************
checkPacketVersion(): Verifies that the header version is supported by the capture software
    Input:  iqHeaderPtr: (int*) Pointer to the IQ header struct in memory
    Ouput:  result (Bool): True if the capture software supports the header version
***************************************************************************** */
bool checkPacketVersion(struct iq_header_struct* iqHeaderPtr)
{
    // Get the pointer to start of the ring buffer location
    bool result = false;
    // Check the packet sync word at byte address zero
    if (iqHeaderPtr->header_version == HEADER_VERSION)
    {
        result = true;
    }
    return result;
}

/* *****************************************************************************
formatField(): Convert integer value to a string of a specified number of characters.
    Input: inputValue (int) field value to be output
            fieldSize (int): Length of the field in number of characters
    Ouput: result (int):
***************************************************************************** */
std::string formatField(int inputValue, int fieldSize)
{
    // Create the base string of the input value
    std::string outputString = std::to_string(inputValue);
    // See if the string is long enough
    int stringLengthDif = fieldSize - outputString.size();
    // Pad zeros in front of the number if required
    while (stringLengthDif > 0)
    {
        outputString = "0" + outputString;
        stringLengthDif--;
    }
    return outputString;
}

/* *****************************************************************************
getSHA512Hash(): Returns the hexadecimal string SHA512 hash of a given file using Open SSL.
    Input:  metaFileStr (const char*): Pointer to the start of the meta file string
            hashBuffer (char*): Pointer to the output buffer where the hash is to be stored
    Ouput:  return 0 if nominal, a negative number if there was an error.
***************************************************************************** */
int getSHA512Hash(const char* metaFileStr, char* hashBuffer)
{
    // Get the has of the function using OpenSSl
    // Create a Message Digest context
    EVP_MD_CTX* mdctx;
    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL)
    {
        log_error("Failed to create a message digest context (See Open SSL EVP)");
        return (FILE_PROCESSING_ERROR);
    }
    // Initialise the context by identifying the algorithm to be used (built-in algorithms are defined in evp.h)
    int testEVP = EVP_DigestInit_ex(mdctx, EVP_sha512(),NULL);
    if (1 != testEVP)
    {
        log_error(
            "Failed to initialize the context by identifying the algorithm to be used (built-in algorithms are defined in evp.h) (See Open SSL EVP)");
        return (FILE_PROCESSING_ERROR);
    }
    // Provide the message whose digest needs to be calculated
    size_t stringSize = strlen(metaFileStr);
    testEVP = EVP_DigestUpdate(mdctx, metaFileStr, stringSize);
    if (1 != testEVP)
    {
        log_error("Failed to provide the message whose digest needs to be calculated. (See Open SSL EVP)");
        return (FILE_PROCESSING_ERROR);
    }
    // Extract the hash from the digest buffer
    unsigned long md_len = EVP_MAX_MD_SIZE;
    unsigned char digest[EVP_MAX_MD_SIZE];
    testEVP = EVP_DigestFinal_ex(mdctx, digest, NULL);
    if (1 != testEVP)
    {
        log_error("Failed to calculate the digest. (See Open SSL EVP)");
        return (FILE_PROCESSING_ERROR);
    }
    // Convert the 64-bit decimal to a hexadecimal string
    size_t str_n = (EVP_MAX_MD_SIZE * 2 + 1);
    size_t* strlength;
    OPENSSL_buf2hexstr_ex(hashBuffer, str_n, strlength, digest, md_len,NULL);
    // Destry the Message Digest context
    EVP_MD_CTX_destroy(mdctx);
    //Nominal return
    return (0);
}

/* *****************************************************************************
makeSigMF(int* bufferStartPointer): Creates a SigMF file for a given packet
    Input: bufferStartPtr (int*): Pointer to the start of an IQ packet in memory
           iqHeaderPtr: (int*) Pointer to the IQ header struct in memory
           directory: (std::string) String containing the filepath to the directory
    Ouput:  return 0 if nominal, a negative number if there was an error.
***************************************************************************** */
int makeSigMF(int* bufferStartPtr, struct iq_header_struct* iqHeaderPtr, std::string directory)
{
    /* *****************************************************************************
     Get the time stamp
    ***************************************************************************** */
    // Get the time_stamp packet field from the packet which gives the number of integer milliseconds since the unix epoch
    int milisecondTime = iqHeaderPtr->time_stamp % 1000;
    // Save the millisecond string
    std::string msString = formatField(milisecondTime, 3);
    // Get the whole seconds since the unix epoch and save as a time_t objectt
    std::time_t packetTimeStampSeconds = (uint64_t)(iqHeaderPtr->time_stamp / 1000);
    // Get the structure holding a calendar date and time broken down into its components
    std::tm* componentTime = gmtime(&packetTimeStampSeconds);
    // Get the other parts of the date stamp
    // The tm year is given in years since 1900
    std::string yearStr = formatField((componentTime->tm_year + 1900), 4);
    // The tm year is given as months since January
    std::string monStr = formatField((componentTime->tm_mon + 1), 2);
    // Get the day of the month
    std::string dayStr = formatField((componentTime->tm_mday), 2);
    // Get the hour of the day
    std::string hrStr = formatField((componentTime->tm_hour), 2);
    //Get the minute of the hour
    std::string minStr = formatField((componentTime->tm_min), 2);
    // Get the integer seconds of the collect
    std::string secStr = formatField((componentTime->tm_sec), 2);
    // Build the date/time struct
    // The first part of every filename uses the same date/time starting part
    std::string filenameDateTime = yearStr + "-" + monStr + "-" + dayStr + "-" + hrStr + "-" + minStr + "-" + secStr +
        "-" + msString + "-";
    // Create the collection filename (Needed for the SigMF metadata file)
    std::string collectionFilename = filenameDateTime + "Z-KRAKEN.sigmf-collection";
    // Create each metadata file
    // Allocate memory for the hash for each metafile (Needed for the collection file)
    // First allocate an array of pointers
    char** hashBuffer = (char**)calloc(iqHeaderPtr->active_ant_chs, sizeof(char*));
    // For each pointer allocate the memory for the string
    for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
    {
        hashBuffer[i] = (char*)calloc((EVP_MAX_MD_SIZE * 2 + 1), sizeof(char));
    }
    /* *****************************************************************************
    Create the SigMF Recording Metadata JSON for each channel
    ***************************************************************************** */
    // Iterate through each channel
    for (int channelNumber = 0; channelNumber < iqHeaderPtr->active_ant_chs; channelNumber++)
    {
        // Create the rapidjson buffer
        rapidjson::StringBuffer s;
        // Create the rapidjson write object
        rapidjson::PrettyWriter<rapidjson::StringBuffer> recordingMetaWriter(s);
        // Start the JSON file definition
        recordingMetaWriter.StartObject(); // Start JSON file definition
        recordingMetaWriter.Key("global"); // Start the root-level global object
        recordingMetaWriter.StartObject(); // Start the root-level global object
        recordingMetaWriter.Key("core:datatype"); // Add the datatype field
        recordingMetaWriter.String(DATASET_FORMAT);
        recordingMetaWriter.Key("core:sample_rate"); // Add the sample rate field
        recordingMetaWriter.Uint64(iqHeaderPtr->sampling_freq);
        recordingMetaWriter.Key("core:collection"); // Add the collection filename string associated with the recording
        recordingMetaWriter.String(collectionFilename.c_str());
        // Create the description text of the field which indicates the channel number
        std::string descriptionText = ("KrakenSDR Coherent Channel " + formatField(channelNumber, 2) + " of " +
            formatField(iqHeaderPtr->active_ant_chs, 2));
        recordingMetaWriter.Key("core:description");
        recordingMetaWriter.String(descriptionText.c_str());
        recordingMetaWriter.Key("core:hw"); // Add the hardware identification field
        recordingMetaWriter.String(iqHeaderPtr->hardware_id);
        recordingMetaWriter.Key("core:version"); // Add the version field
        recordingMetaWriter.String(SIGMF_SPEC);
        recordingMetaWriter.EndObject(); // End the root-level global object
        recordingMetaWriter.Key("captures"); // Start the root-level captures array
        // Captures is required by the SigMF spec to be an array, but we only write one capture object for the metadata file since the collection parameters don't change
        recordingMetaWriter.StartArray();
        recordingMetaWriter.StartObject(); // Start the single capture object
        recordingMetaWriter.Key("core:sample_start");
        //  Add sample start field index of the first sample of the chunk (Note only one chunk is used)
        recordingMetaWriter.Int(0);
        // Create the ISO-8601 formated datetime stamp
        std::string dateTimeISO8601 = yearStr + "-" + monStr + "-" + dayStr + "T" + hrStr + ":" + minStr + ":" + secStr
            + "." + msString + "Z";
        recordingMetaWriter.Key("core:datetime");
        // Add ISO-8601 datetime stamp indicating the time at core:sample_start
        recordingMetaWriter.String((dateTimeISO8601.c_str()));
        recordingMetaWriter.Key("core:frequency"); // Add the center frequency field
        recordingMetaWriter.Uint64(iqHeaderPtr->rf_center_freq);
        // Future Add - Geoolocation
        // writer.Key("core:geolocation");
        // writer.String("This is where the GEO JSON will be");
        recordingMetaWriter.EndObject(); // End the single capture object
        recordingMetaWriter.EndArray();
        recordingMetaWriter.Key("annotations"); // Start the root-level captures array
        recordingMetaWriter.StartArray();
        recordingMetaWriter.EndArray();
        recordingMetaWriter.EndObject(); // End JSON file definition
        // Write the JSON to the file
        // Append the file name to the specified file path
        std::string metaFilename = filenameDateTime + "CH" + formatField(channelNumber, 2) + "-KRAKEN.sigmf-meta";
        std::string metaFilePath = directory + metaFilename;
        /* *****************************************************************************
        Get a hash for a metadata file (required for the collectin file)
        ***************************************************************************** */
        int checkHash = getSHA512Hash(s.GetString(), hashBuffer[channelNumber]);
        // Return if there was an error making the hash
        if (checkHash < 0)
        {
            log_fatal("Failed to create a SHA512 hash for SigMF Collection File. Terminating.");
            // Garbage collect
            for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
            {
                delete hashBuffer[i];
                hashBuffer[i] = nullptr;
            }
            delete hashBuffer;
            hashBuffer = nullptr;
            // End the thread
            return (FILE_PROCESSING_ERROR);
        }
        /* *****************************************************************************
        Write the metadata file
        ***************************************************************************** */
        FILE* fptr;
        fptr = fopen(metaFilePath.c_str(), "w");
        if (fptr == NULL)
        {
            log_fatal("Failed to open metadata file. Terminating.");
            // Garbage collect
            for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
            {
                delete hashBuffer[i];
                hashBuffer[i] = nullptr;
            }
            delete hashBuffer;
            hashBuffer = nullptr;
            // End the thread
            return (FILE_PROCESSING_ERROR);
        }
        // Send the JSON to the file
        int writeSize = fprintf(fptr, s.GetString());
        if (writeSize < 0)
        {
            log_fatal("Failed to write SigMF MetaData File. Terminating.");
            // Garbage collect
            for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
            {
                delete hashBuffer[i];
                hashBuffer[i] = nullptr;
            }
            delete hashBuffer;
            hashBuffer = nullptr;
            // End the thread
            return (FILE_PROCESSING_ERROR);
        }
        else
        {
            log_debug("Writing SigMF Metadata File: %s", metaFilename.c_str());
        }
        // Close the file
        fclose(fptr);
        /* *****************************************************************************
        Write the data file
        ***************************************************************************** */
        // Get the filename for the data file
        std::string dataFilename = filenameDateTime + "CH" + formatField(channelNumber, 2) + "-KRAKEN.sigmf-data";
        // Get the path to where the data will be sent
        std::string dataFilePath = directory + dataFilename;
        fptr = fopen(dataFilePath.c_str(), "w");
        if (fptr == NULL)
        {
            log_fatal("Failed to open data file. Terminating.");
            // Garbage collect
            for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
            {
                delete hashBuffer[i];
                hashBuffer[i] = nullptr;
            }
            delete hashBuffer;
            hashBuffer = nullptr;
            // End the thread
            return (FILE_PROCESSING_ERROR);
        }
        int dataStartOffset = (HEADER_SIZE + (channelNumber * iqHeaderPtr->cpi_length * 2));
        size_t transfersize = fwrite((bufferStartPtr + dataStartOffset), sizeof(int), (iqHeaderPtr->cpi_length * 2),
                                     fptr);
        if (transfersize == 0)
        {
            log_fatal("Failed to write SigMF Data File. Terminating.");
            // Garbage collect
            for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
            {
                delete hashBuffer[i];
                hashBuffer[i] = nullptr;
            }
            delete hashBuffer;
            hashBuffer = nullptr;
            // End the thread
            return (FILE_PROCESSING_ERROR);
        }
        else
        {
            log_debug("Writing SigMF Data File: %s", dataFilename.c_str());
        }
        fclose(fptr);
    }
    /* *****************************************************************************
    Populate the SigMF Collection Metadata JSON
    ***************************************************************************** */
    // Create the rapidjson buffer
    rapidjson::StringBuffer s2;
    // Create the rapidjson write object
    rapidjson::PrettyWriter<rapidjson::StringBuffer> collectionMetaWriter(s2);;
    // Start the JSON file definition
    collectionMetaWriter.StartObject(); // Start JSON file definition
    collectionMetaWriter.Key("core:version"); // Add the version field
    collectionMetaWriter.String(SIGMF_SPEC);
    collectionMetaWriter.Key("core:streams"); // Add the streams field which ties the recording ot the collection
    collectionMetaWriter.StartArray();
    for (int channelNumber = 0; channelNumber < iqHeaderPtr->active_ant_chs; channelNumber++)
    {
        collectionMetaWriter.StartObject(); // Create the object the stream entry object
        collectionMetaWriter.Key("name");
        // Get each base name for each SigMF recording
        std::string metaFileBaseName = filenameDateTime + "CH" + formatField(channelNumber, 2) + "-KRAKEN";
        collectionMetaWriter.String(metaFileBaseName.c_str());
        collectionMetaWriter.Key("hash");
        // Write the hash of the basefilename
        collectionMetaWriter.String(hashBuffer[channelNumber]);
        collectionMetaWriter.EndObject(); // Close the object the stream entry object
    }
    collectionMetaWriter.EndArray();
    collectionMetaWriter.EndObject(); // End JSON file definition
    // Write the JSON to the file
    // Append the file name to the specified file path
    std::string collectionFilePath = directory + collectionFilename;
    // Get the file pointer
    FILE* fptr;
    fptr = fopen(collectionFilePath.c_str(), "w");
    if (fptr == NULL)
    {
        log_fatal("Failed to open collection file. Terminating.");
        // Garbage collect
        for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
        {
            delete hashBuffer[i];
            hashBuffer[i] = nullptr;
        }
        delete hashBuffer;
        hashBuffer = nullptr;
        // End the thread
        return (FILE_PROCESSING_ERROR);
    }
    // Send the JSON to the file
    int writeSize = fprintf(fptr, s2.GetString());
    if (writeSize < 0)
    {
        log_fatal("Failed to write SigMF Collection File. Terminating.");
        // Garbage collect
        for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
        {
            delete hashBuffer[i];
            hashBuffer[i] = nullptr;
        }
        delete hashBuffer;
        hashBuffer = nullptr;
        // End the thread
        return (FILE_PROCESSING_ERROR);
    }
    else
    {
        log_debug("Writing SigMF Collection File: %s", collectionFilename.c_str());
    }
    fclose(fptr);
    /* *****************************************************************************
    Garbage Collection
    ***************************************************************************** */
    for (int i = 0; i < iqHeaderPtr->active_ant_chs; i++)
    {
        delete hashBuffer[i];
        hashBuffer[i] = nullptr;
    }
    delete hashBuffer;
    hashBuffer = nullptr;
    // Nominal return
    return (0);
}
