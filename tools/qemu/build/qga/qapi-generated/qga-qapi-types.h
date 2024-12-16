/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef QGA_QAPI_TYPES_H
#define QGA_QAPI_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include "qapi/qmp/qobject.h"

#ifndef QAPI_TYPES_BUILTIN
#define QAPI_TYPES_BUILTIN


typedef struct anyList anyList;

struct anyList {
    union {
        QObject *value;
        uint64_t padding;
    };
    anyList *next;
};

void qapi_free_anyList(anyList *obj);

typedef struct boolList boolList;

struct boolList {
    union {
        bool value;
        uint64_t padding;
    };
    boolList *next;
};

void qapi_free_boolList(boolList *obj);

typedef struct int16List int16List;

struct int16List {
    union {
        int16_t value;
        uint64_t padding;
    };
    int16List *next;
};

void qapi_free_int16List(int16List *obj);

typedef struct int32List int32List;

struct int32List {
    union {
        int32_t value;
        uint64_t padding;
    };
    int32List *next;
};

void qapi_free_int32List(int32List *obj);

typedef struct int64List int64List;

struct int64List {
    union {
        int64_t value;
        uint64_t padding;
    };
    int64List *next;
};

void qapi_free_int64List(int64List *obj);

typedef struct int8List int8List;

struct int8List {
    union {
        int8_t value;
        uint64_t padding;
    };
    int8List *next;
};

void qapi_free_int8List(int8List *obj);

typedef struct intList intList;

struct intList {
    union {
        int64_t value;
        uint64_t padding;
    };
    intList *next;
};

void qapi_free_intList(intList *obj);

typedef struct numberList numberList;

struct numberList {
    union {
        double value;
        uint64_t padding;
    };
    numberList *next;
};

void qapi_free_numberList(numberList *obj);

typedef struct sizeList sizeList;

struct sizeList {
    union {
        uint64_t value;
        uint64_t padding;
    };
    sizeList *next;
};

void qapi_free_sizeList(sizeList *obj);

typedef struct strList strList;

struct strList {
    union {
        char *value;
        uint64_t padding;
    };
    strList *next;
};

void qapi_free_strList(strList *obj);

typedef struct uint16List uint16List;

struct uint16List {
    union {
        uint16_t value;
        uint64_t padding;
    };
    uint16List *next;
};

void qapi_free_uint16List(uint16List *obj);

typedef struct uint32List uint32List;

struct uint32List {
    union {
        uint32_t value;
        uint64_t padding;
    };
    uint32List *next;
};

void qapi_free_uint32List(uint32List *obj);

typedef struct uint64List uint64List;

struct uint64List {
    union {
        uint64_t value;
        uint64_t padding;
    };
    uint64List *next;
};

void qapi_free_uint64List(uint64List *obj);

typedef struct uint8List uint8List;

struct uint8List {
    union {
        uint8_t value;
        uint64_t padding;
    };
    uint8List *next;
};

void qapi_free_uint8List(uint8List *obj);

#endif /* QAPI_TYPES_BUILTIN */


typedef struct GuestAgentCommandInfo GuestAgentCommandInfo;

typedef struct GuestAgentCommandInfoList GuestAgentCommandInfoList;

typedef struct GuestAgentInfo GuestAgentInfo;

typedef struct GuestDiskAddress GuestDiskAddress;

typedef struct GuestDiskAddressList GuestDiskAddressList;

typedef enum GuestDiskBusType {
    GUEST_DISK_BUS_TYPE_IDE = 0,
    GUEST_DISK_BUS_TYPE_FDC = 1,
    GUEST_DISK_BUS_TYPE_SCSI = 2,
    GUEST_DISK_BUS_TYPE_VIRTIO = 3,
    GUEST_DISK_BUS_TYPE_XEN = 4,
    GUEST_DISK_BUS_TYPE_USB = 5,
    GUEST_DISK_BUS_TYPE_UML = 6,
    GUEST_DISK_BUS_TYPE_SATA = 7,
    GUEST_DISK_BUS_TYPE_SD = 8,
    GUEST_DISK_BUS_TYPE_UNKNOWN = 9,
    GUEST_DISK_BUS_TYPE_IEEE1394 = 10,
    GUEST_DISK_BUS_TYPE_SSA = 11,
    GUEST_DISK_BUS_TYPE_FIBRE = 12,
    GUEST_DISK_BUS_TYPE_RAID = 13,
    GUEST_DISK_BUS_TYPE_ISCSI = 14,
    GUEST_DISK_BUS_TYPE_SAS = 15,
    GUEST_DISK_BUS_TYPE_MMC = 16,
    GUEST_DISK_BUS_TYPE_VIRTUAL = 17,
    GUEST_DISK_BUS_TYPE_FILE_BACKED_VIRTUAL = 18,
    GUEST_DISK_BUS_TYPE_MAX = 19,
} GuestDiskBusType;

extern const char *const GuestDiskBusType_lookup[];

typedef struct GuestExec GuestExec;

typedef struct GuestExecStatus GuestExecStatus;

typedef struct GuestFileRead GuestFileRead;

typedef struct GuestFileSeek GuestFileSeek;

typedef struct GuestFileWrite GuestFileWrite;

typedef struct GuestFilesystemInfo GuestFilesystemInfo;

typedef struct GuestFilesystemInfoList GuestFilesystemInfoList;

typedef struct GuestFilesystemTrimResponse GuestFilesystemTrimResponse;

typedef struct GuestFilesystemTrimResult GuestFilesystemTrimResult;

typedef struct GuestFilesystemTrimResultList GuestFilesystemTrimResultList;

typedef enum GuestFsfreezeStatus {
    GUEST_FSFREEZE_STATUS_THAWED = 0,
    GUEST_FSFREEZE_STATUS_FROZEN = 1,
    GUEST_FSFREEZE_STATUS_MAX = 2,
} GuestFsfreezeStatus;

extern const char *const GuestFsfreezeStatus_lookup[];

typedef struct GuestIpAddress GuestIpAddress;

typedef struct GuestIpAddressList GuestIpAddressList;

typedef enum GuestIpAddressType {
    GUEST_IP_ADDRESS_TYPE_IPV4 = 0,
    GUEST_IP_ADDRESS_TYPE_IPV6 = 1,
    GUEST_IP_ADDRESS_TYPE_MAX = 2,
} GuestIpAddressType;

extern const char *const GuestIpAddressType_lookup[];

typedef struct GuestLogicalProcessor GuestLogicalProcessor;

typedef struct GuestLogicalProcessorList GuestLogicalProcessorList;

typedef struct GuestMemoryBlock GuestMemoryBlock;

typedef struct GuestMemoryBlockInfo GuestMemoryBlockInfo;

typedef struct GuestMemoryBlockList GuestMemoryBlockList;

typedef struct GuestMemoryBlockResponse GuestMemoryBlockResponse;

typedef struct GuestMemoryBlockResponseList GuestMemoryBlockResponseList;

typedef enum GuestMemoryBlockResponseType {
    GUEST_MEMORY_BLOCK_RESPONSE_TYPE_SUCCESS = 0,
    GUEST_MEMORY_BLOCK_RESPONSE_TYPE_NOT_FOUND = 1,
    GUEST_MEMORY_BLOCK_RESPONSE_TYPE_OPERATION_NOT_SUPPORTED = 2,
    GUEST_MEMORY_BLOCK_RESPONSE_TYPE_OPERATION_FAILED = 3,
    GUEST_MEMORY_BLOCK_RESPONSE_TYPE_MAX = 4,
} GuestMemoryBlockResponseType;

extern const char *const GuestMemoryBlockResponseType_lookup[];

typedef struct GuestNetworkInterface GuestNetworkInterface;

typedef struct GuestNetworkInterfaceList GuestNetworkInterfaceList;

typedef struct GuestPCIAddress GuestPCIAddress;

struct GuestAgentCommandInfo {
    char *name;
    bool enabled;
    bool success_response;
};

void qapi_free_GuestAgentCommandInfo(GuestAgentCommandInfo *obj);

struct GuestAgentCommandInfoList {
    union {
        GuestAgentCommandInfo *value;
        uint64_t padding;
    };
    GuestAgentCommandInfoList *next;
};

void qapi_free_GuestAgentCommandInfoList(GuestAgentCommandInfoList *obj);

struct GuestAgentInfo {
    char *version;
    GuestAgentCommandInfoList *supported_commands;
};

void qapi_free_GuestAgentInfo(GuestAgentInfo *obj);

struct GuestDiskAddress {
    GuestPCIAddress *pci_controller;
    GuestDiskBusType bus_type;
    int64_t bus;
    int64_t target;
    int64_t unit;
};

void qapi_free_GuestDiskAddress(GuestDiskAddress *obj);

struct GuestDiskAddressList {
    union {
        GuestDiskAddress *value;
        uint64_t padding;
    };
    GuestDiskAddressList *next;
};

void qapi_free_GuestDiskAddressList(GuestDiskAddressList *obj);

struct GuestExec {
    int64_t pid;
};

void qapi_free_GuestExec(GuestExec *obj);

struct GuestExecStatus {
    bool exited;
    bool has_exitcode;
    int64_t exitcode;
    bool has_signal;
    int64_t signal;
    bool has_out_data;
    char *out_data;
    bool has_err_data;
    char *err_data;
    bool has_out_truncated;
    bool out_truncated;
    bool has_err_truncated;
    bool err_truncated;
};

void qapi_free_GuestExecStatus(GuestExecStatus *obj);

struct GuestFileRead {
    int64_t count;
    char *buf_b64;
    bool eof;
};

void qapi_free_GuestFileRead(GuestFileRead *obj);

struct GuestFileSeek {
    int64_t position;
    bool eof;
};

void qapi_free_GuestFileSeek(GuestFileSeek *obj);

struct GuestFileWrite {
    int64_t count;
    bool eof;
};

void qapi_free_GuestFileWrite(GuestFileWrite *obj);

struct GuestFilesystemInfo {
    char *name;
    char *mountpoint;
    char *type;
    GuestDiskAddressList *disk;
};

void qapi_free_GuestFilesystemInfo(GuestFilesystemInfo *obj);

struct GuestFilesystemInfoList {
    union {
        GuestFilesystemInfo *value;
        uint64_t padding;
    };
    GuestFilesystemInfoList *next;
};

void qapi_free_GuestFilesystemInfoList(GuestFilesystemInfoList *obj);

struct GuestFilesystemTrimResponse {
    GuestFilesystemTrimResultList *paths;
};

void qapi_free_GuestFilesystemTrimResponse(GuestFilesystemTrimResponse *obj);

struct GuestFilesystemTrimResult {
    char *path;
    bool has_trimmed;
    int64_t trimmed;
    bool has_minimum;
    int64_t minimum;
    bool has_error;
    char *error;
};

void qapi_free_GuestFilesystemTrimResult(GuestFilesystemTrimResult *obj);

struct GuestFilesystemTrimResultList {
    union {
        GuestFilesystemTrimResult *value;
        uint64_t padding;
    };
    GuestFilesystemTrimResultList *next;
};

void qapi_free_GuestFilesystemTrimResultList(GuestFilesystemTrimResultList *obj);

struct GuestIpAddress {
    char *ip_address;
    GuestIpAddressType ip_address_type;
    int64_t prefix;
};

void qapi_free_GuestIpAddress(GuestIpAddress *obj);

struct GuestIpAddressList {
    union {
        GuestIpAddress *value;
        uint64_t padding;
    };
    GuestIpAddressList *next;
};

void qapi_free_GuestIpAddressList(GuestIpAddressList *obj);

struct GuestLogicalProcessor {
    int64_t logical_id;
    bool online;
    bool has_can_offline;
    bool can_offline;
};

void qapi_free_GuestLogicalProcessor(GuestLogicalProcessor *obj);

struct GuestLogicalProcessorList {
    union {
        GuestLogicalProcessor *value;
        uint64_t padding;
    };
    GuestLogicalProcessorList *next;
};

void qapi_free_GuestLogicalProcessorList(GuestLogicalProcessorList *obj);

struct GuestMemoryBlock {
    uint64_t phys_index;
    bool online;
    bool has_can_offline;
    bool can_offline;
};

void qapi_free_GuestMemoryBlock(GuestMemoryBlock *obj);

struct GuestMemoryBlockInfo {
    uint64_t size;
};

void qapi_free_GuestMemoryBlockInfo(GuestMemoryBlockInfo *obj);

struct GuestMemoryBlockList {
    union {
        GuestMemoryBlock *value;
        uint64_t padding;
    };
    GuestMemoryBlockList *next;
};

void qapi_free_GuestMemoryBlockList(GuestMemoryBlockList *obj);

struct GuestMemoryBlockResponse {
    uint64_t phys_index;
    GuestMemoryBlockResponseType response;
    bool has_error_code;
    int64_t error_code;
};

void qapi_free_GuestMemoryBlockResponse(GuestMemoryBlockResponse *obj);

struct GuestMemoryBlockResponseList {
    union {
        GuestMemoryBlockResponse *value;
        uint64_t padding;
    };
    GuestMemoryBlockResponseList *next;
};

void qapi_free_GuestMemoryBlockResponseList(GuestMemoryBlockResponseList *obj);

struct GuestNetworkInterface {
    char *name;
    bool has_hardware_address;
    char *hardware_address;
    bool has_ip_addresses;
    GuestIpAddressList *ip_addresses;
};

void qapi_free_GuestNetworkInterface(GuestNetworkInterface *obj);

struct GuestNetworkInterfaceList {
    union {
        GuestNetworkInterface *value;
        uint64_t padding;
    };
    GuestNetworkInterfaceList *next;
};

void qapi_free_GuestNetworkInterfaceList(GuestNetworkInterfaceList *obj);

struct GuestPCIAddress {
    int64_t domain;
    int64_t bus;
    int64_t slot;
    int64_t function;
};

void qapi_free_GuestPCIAddress(GuestPCIAddress *obj);

#endif
