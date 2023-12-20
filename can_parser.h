
#ifndef CAN_PARSER_H
#define CAN_PARSER_H


#define RELEASE_CNFG
#ifndef RELEASE_CNFG
#define DEBUG_CNFG
#endif  //DEBUG_CNFG


#define DEFAULT_FILEPATH    "C:/test_proj_can/test_can_vscode/CZ.log"
#define PATH_LEN_MAX        100
#define FILEBUF_LEN_MAX     2000000     //file max lenght - 2 Mb
#define READBYTES_CNT       10000
#define ID_CNT_MAX          10000
#define DEFAULT_INVERSIONS  4
#define DEFAULT_BITMASK     3
#define DEFAULT_BITSCOUNT   2

// this structure stores the frame IDs and their count
typedef struct
{
    char *frame_id;             //current frame ID string
    unsigned int id_count;      //frames count of current ID
    unsigned char bytes_count;  //bytes count in one frame of current ID
} ID_count;


#endif  //CAN_PARSER_H
