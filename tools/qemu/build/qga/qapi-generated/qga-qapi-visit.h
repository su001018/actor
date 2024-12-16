/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI visitor functions
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

#ifndef QGA_QAPI_VISIT_H
#define QGA_QAPI_VISIT_H

#include "qapi/visitor.h"
#include "qga-qapi-types.h"


#ifndef QAPI_VISIT_BUILTIN
#define QAPI_VISIT_BUILTIN

void visit_type_anyList(Visitor *v, anyList **obj, const char *name, Error **errp);
void visit_type_boolList(Visitor *v, boolList **obj, const char *name, Error **errp);
void visit_type_int16List(Visitor *v, int16List **obj, const char *name, Error **errp);
void visit_type_int32List(Visitor *v, int32List **obj, const char *name, Error **errp);
void visit_type_int64List(Visitor *v, int64List **obj, const char *name, Error **errp);
void visit_type_int8List(Visitor *v, int8List **obj, const char *name, Error **errp);
void visit_type_intList(Visitor *v, intList **obj, const char *name, Error **errp);
void visit_type_numberList(Visitor *v, numberList **obj, const char *name, Error **errp);
void visit_type_sizeList(Visitor *v, sizeList **obj, const char *name, Error **errp);
void visit_type_strList(Visitor *v, strList **obj, const char *name, Error **errp);
void visit_type_uint16List(Visitor *v, uint16List **obj, const char *name, Error **errp);
void visit_type_uint32List(Visitor *v, uint32List **obj, const char *name, Error **errp);
void visit_type_uint64List(Visitor *v, uint64List **obj, const char *name, Error **errp);
void visit_type_uint8List(Visitor *v, uint8List **obj, const char *name, Error **errp);

#endif /* QAPI_VISIT_BUILTIN */

void visit_type_GuestAgentCommandInfo(Visitor *v, GuestAgentCommandInfo **obj, const char *name, Error **errp);
void visit_type_GuestAgentCommandInfoList(Visitor *v, GuestAgentCommandInfoList **obj, const char *name, Error **errp);
void visit_type_GuestAgentInfo(Visitor *v, GuestAgentInfo **obj, const char *name, Error **errp);
void visit_type_GuestDiskAddress(Visitor *v, GuestDiskAddress **obj, const char *name, Error **errp);
void visit_type_GuestDiskAddressList(Visitor *v, GuestDiskAddressList **obj, const char *name, Error **errp);
void visit_type_GuestDiskBusType(Visitor *v, GuestDiskBusType *obj, const char *name, Error **errp);
void visit_type_GuestExec(Visitor *v, GuestExec **obj, const char *name, Error **errp);
void visit_type_GuestExecStatus(Visitor *v, GuestExecStatus **obj, const char *name, Error **errp);
void visit_type_GuestFileRead(Visitor *v, GuestFileRead **obj, const char *name, Error **errp);
void visit_type_GuestFileSeek(Visitor *v, GuestFileSeek **obj, const char *name, Error **errp);
void visit_type_GuestFileWrite(Visitor *v, GuestFileWrite **obj, const char *name, Error **errp);
void visit_type_GuestFilesystemInfo(Visitor *v, GuestFilesystemInfo **obj, const char *name, Error **errp);
void visit_type_GuestFilesystemInfoList(Visitor *v, GuestFilesystemInfoList **obj, const char *name, Error **errp);
void visit_type_GuestFilesystemTrimResponse(Visitor *v, GuestFilesystemTrimResponse **obj, const char *name, Error **errp);
void visit_type_GuestFilesystemTrimResult(Visitor *v, GuestFilesystemTrimResult **obj, const char *name, Error **errp);
void visit_type_GuestFilesystemTrimResultList(Visitor *v, GuestFilesystemTrimResultList **obj, const char *name, Error **errp);
void visit_type_GuestFsfreezeStatus(Visitor *v, GuestFsfreezeStatus *obj, const char *name, Error **errp);
void visit_type_GuestIpAddress(Visitor *v, GuestIpAddress **obj, const char *name, Error **errp);
void visit_type_GuestIpAddressList(Visitor *v, GuestIpAddressList **obj, const char *name, Error **errp);
void visit_type_GuestIpAddressType(Visitor *v, GuestIpAddressType *obj, const char *name, Error **errp);
void visit_type_GuestLogicalProcessor(Visitor *v, GuestLogicalProcessor **obj, const char *name, Error **errp);
void visit_type_GuestLogicalProcessorList(Visitor *v, GuestLogicalProcessorList **obj, const char *name, Error **errp);
void visit_type_GuestMemoryBlock(Visitor *v, GuestMemoryBlock **obj, const char *name, Error **errp);
void visit_type_GuestMemoryBlockInfo(Visitor *v, GuestMemoryBlockInfo **obj, const char *name, Error **errp);
void visit_type_GuestMemoryBlockList(Visitor *v, GuestMemoryBlockList **obj, const char *name, Error **errp);
void visit_type_GuestMemoryBlockResponse(Visitor *v, GuestMemoryBlockResponse **obj, const char *name, Error **errp);
void visit_type_GuestMemoryBlockResponseList(Visitor *v, GuestMemoryBlockResponseList **obj, const char *name, Error **errp);
void visit_type_GuestMemoryBlockResponseType(Visitor *v, GuestMemoryBlockResponseType *obj, const char *name, Error **errp);
void visit_type_GuestNetworkInterface(Visitor *v, GuestNetworkInterface **obj, const char *name, Error **errp);
void visit_type_GuestNetworkInterfaceList(Visitor *v, GuestNetworkInterfaceList **obj, const char *name, Error **errp);
void visit_type_GuestPCIAddress(Visitor *v, GuestPCIAddress **obj, const char *name, Error **errp);

#endif
