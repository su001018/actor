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

#include "qemu-common.h"
#include "qga-qapi-visit.h"

static void visit_type_GuestAgentCommandInfo_fields(Visitor *v, GuestAgentCommandInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, &(*obj)->name, "name", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->enabled, "enabled", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->success_response, "success-response", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestAgentCommandInfo(Visitor *v, GuestAgentCommandInfo **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestAgentCommandInfo", name, sizeof(GuestAgentCommandInfo), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestAgentCommandInfo_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestAgentCommandInfoList(Visitor *v, GuestAgentCommandInfoList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestAgentCommandInfoList *native_i = (GuestAgentCommandInfoList *)i;
        visit_type_GuestAgentCommandInfo(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

static void visit_type_GuestAgentInfo_fields(Visitor *v, GuestAgentInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, &(*obj)->version, "version", &err);
    if (err) {
        goto out;
    }
    visit_type_GuestAgentCommandInfoList(v, &(*obj)->supported_commands, "supported_commands", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestAgentInfo(Visitor *v, GuestAgentInfo **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestAgentInfo", name, sizeof(GuestAgentInfo), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestAgentInfo_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestDiskAddress_fields(Visitor *v, GuestDiskAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_GuestPCIAddress(v, &(*obj)->pci_controller, "pci-controller", &err);
    if (err) {
        goto out;
    }
    visit_type_GuestDiskBusType(v, &(*obj)->bus_type, "bus-type", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->bus, "bus", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->target, "target", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->unit, "unit", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestDiskAddress(Visitor *v, GuestDiskAddress **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestDiskAddress", name, sizeof(GuestDiskAddress), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestDiskAddress_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestDiskAddressList(Visitor *v, GuestDiskAddressList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestDiskAddressList *native_i = (GuestDiskAddressList *)i;
        visit_type_GuestDiskAddress(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

void visit_type_GuestDiskBusType(Visitor *v, GuestDiskBusType *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, GuestDiskBusType_lookup, "GuestDiskBusType", name, errp);
}

static void visit_type_GuestExec_fields(Visitor *v, GuestExec **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->pid, "pid", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestExec(Visitor *v, GuestExec **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestExec", name, sizeof(GuestExec), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestExec_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestExecStatus_fields(Visitor *v, GuestExecStatus **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_bool(v, &(*obj)->exited, "exited", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &(*obj)->has_exitcode, "exitcode", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_exitcode) {
        visit_type_int(v, &(*obj)->exitcode, "exitcode", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_signal, "signal", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_signal) {
        visit_type_int(v, &(*obj)->signal, "signal", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_out_data, "out-data", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_out_data) {
        visit_type_str(v, &(*obj)->out_data, "out-data", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_err_data, "err-data", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_err_data) {
        visit_type_str(v, &(*obj)->err_data, "err-data", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_out_truncated, "out-truncated", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_out_truncated) {
        visit_type_bool(v, &(*obj)->out_truncated, "out-truncated", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_err_truncated, "err-truncated", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_err_truncated) {
        visit_type_bool(v, &(*obj)->err_truncated, "err-truncated", &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestExecStatus(Visitor *v, GuestExecStatus **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestExecStatus", name, sizeof(GuestExecStatus), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestExecStatus_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestFileRead_fields(Visitor *v, GuestFileRead **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->count, "count", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &(*obj)->buf_b64, "buf-b64", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->eof, "eof", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestFileRead(Visitor *v, GuestFileRead **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestFileRead", name, sizeof(GuestFileRead), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestFileRead_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestFileSeek_fields(Visitor *v, GuestFileSeek **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->position, "position", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->eof, "eof", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestFileSeek(Visitor *v, GuestFileSeek **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestFileSeek", name, sizeof(GuestFileSeek), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestFileSeek_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestFileWrite_fields(Visitor *v, GuestFileWrite **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->count, "count", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->eof, "eof", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestFileWrite(Visitor *v, GuestFileWrite **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestFileWrite", name, sizeof(GuestFileWrite), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestFileWrite_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestFilesystemInfo_fields(Visitor *v, GuestFilesystemInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, &(*obj)->name, "name", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &(*obj)->mountpoint, "mountpoint", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &(*obj)->type, "type", &err);
    if (err) {
        goto out;
    }
    visit_type_GuestDiskAddressList(v, &(*obj)->disk, "disk", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestFilesystemInfo(Visitor *v, GuestFilesystemInfo **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestFilesystemInfo", name, sizeof(GuestFilesystemInfo), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestFilesystemInfo_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestFilesystemInfoList(Visitor *v, GuestFilesystemInfoList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestFilesystemInfoList *native_i = (GuestFilesystemInfoList *)i;
        visit_type_GuestFilesystemInfo(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

static void visit_type_GuestFilesystemTrimResponse_fields(Visitor *v, GuestFilesystemTrimResponse **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_GuestFilesystemTrimResultList(v, &(*obj)->paths, "paths", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestFilesystemTrimResponse(Visitor *v, GuestFilesystemTrimResponse **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestFilesystemTrimResponse", name, sizeof(GuestFilesystemTrimResponse), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestFilesystemTrimResponse_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestFilesystemTrimResult_fields(Visitor *v, GuestFilesystemTrimResult **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, &(*obj)->path, "path", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &(*obj)->has_trimmed, "trimmed", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_trimmed) {
        visit_type_int(v, &(*obj)->trimmed, "trimmed", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_minimum, "minimum", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_minimum) {
        visit_type_int(v, &(*obj)->minimum, "minimum", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_error, "error", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_error) {
        visit_type_str(v, &(*obj)->error, "error", &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestFilesystemTrimResult(Visitor *v, GuestFilesystemTrimResult **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestFilesystemTrimResult", name, sizeof(GuestFilesystemTrimResult), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestFilesystemTrimResult_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestFilesystemTrimResultList(Visitor *v, GuestFilesystemTrimResultList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestFilesystemTrimResultList *native_i = (GuestFilesystemTrimResultList *)i;
        visit_type_GuestFilesystemTrimResult(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

void visit_type_GuestFsfreezeStatus(Visitor *v, GuestFsfreezeStatus *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, GuestFsfreezeStatus_lookup, "GuestFsfreezeStatus", name, errp);
}

static void visit_type_GuestIpAddress_fields(Visitor *v, GuestIpAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, &(*obj)->ip_address, "ip-address", &err);
    if (err) {
        goto out;
    }
    visit_type_GuestIpAddressType(v, &(*obj)->ip_address_type, "ip-address-type", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->prefix, "prefix", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestIpAddress(Visitor *v, GuestIpAddress **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestIpAddress", name, sizeof(GuestIpAddress), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestIpAddress_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestIpAddressList(Visitor *v, GuestIpAddressList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestIpAddressList *native_i = (GuestIpAddressList *)i;
        visit_type_GuestIpAddress(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

void visit_type_GuestIpAddressType(Visitor *v, GuestIpAddressType *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, GuestIpAddressType_lookup, "GuestIpAddressType", name, errp);
}

static void visit_type_GuestLogicalProcessor_fields(Visitor *v, GuestLogicalProcessor **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->logical_id, "logical-id", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->online, "online", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &(*obj)->has_can_offline, "can-offline", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_can_offline) {
        visit_type_bool(v, &(*obj)->can_offline, "can-offline", &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestLogicalProcessor(Visitor *v, GuestLogicalProcessor **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestLogicalProcessor", name, sizeof(GuestLogicalProcessor), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestLogicalProcessor_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestLogicalProcessorList(Visitor *v, GuestLogicalProcessorList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestLogicalProcessorList *native_i = (GuestLogicalProcessorList *)i;
        visit_type_GuestLogicalProcessor(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

static void visit_type_GuestMemoryBlock_fields(Visitor *v, GuestMemoryBlock **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint64(v, &(*obj)->phys_index, "phys-index", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &(*obj)->online, "online", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &(*obj)->has_can_offline, "can-offline", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_can_offline) {
        visit_type_bool(v, &(*obj)->can_offline, "can-offline", &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestMemoryBlock(Visitor *v, GuestMemoryBlock **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestMemoryBlock", name, sizeof(GuestMemoryBlock), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestMemoryBlock_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

static void visit_type_GuestMemoryBlockInfo_fields(Visitor *v, GuestMemoryBlockInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint64(v, &(*obj)->size, "size", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestMemoryBlockInfo(Visitor *v, GuestMemoryBlockInfo **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestMemoryBlockInfo", name, sizeof(GuestMemoryBlockInfo), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestMemoryBlockInfo_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestMemoryBlockList(Visitor *v, GuestMemoryBlockList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestMemoryBlockList *native_i = (GuestMemoryBlockList *)i;
        visit_type_GuestMemoryBlock(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

static void visit_type_GuestMemoryBlockResponse_fields(Visitor *v, GuestMemoryBlockResponse **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_uint64(v, &(*obj)->phys_index, "phys-index", &err);
    if (err) {
        goto out;
    }
    visit_type_GuestMemoryBlockResponseType(v, &(*obj)->response, "response", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &(*obj)->has_error_code, "error-code", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_error_code) {
        visit_type_int(v, &(*obj)->error_code, "error-code", &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestMemoryBlockResponse(Visitor *v, GuestMemoryBlockResponse **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestMemoryBlockResponse", name, sizeof(GuestMemoryBlockResponse), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestMemoryBlockResponse_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestMemoryBlockResponseList(Visitor *v, GuestMemoryBlockResponseList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestMemoryBlockResponseList *native_i = (GuestMemoryBlockResponseList *)i;
        visit_type_GuestMemoryBlockResponse(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

void visit_type_GuestMemoryBlockResponseType(Visitor *v, GuestMemoryBlockResponseType *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, GuestMemoryBlockResponseType_lookup, "GuestMemoryBlockResponseType", name, errp);
}

static void visit_type_GuestNetworkInterface_fields(Visitor *v, GuestNetworkInterface **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_str(v, &(*obj)->name, "name", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &(*obj)->has_hardware_address, "hardware-address", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_hardware_address) {
        visit_type_str(v, &(*obj)->hardware_address, "hardware-address", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &(*obj)->has_ip_addresses, "ip-addresses", &err);
    if (err) {
        goto out;
    }
    if ((*obj)->has_ip_addresses) {
        visit_type_GuestIpAddressList(v, &(*obj)->ip_addresses, "ip-addresses", &err);
        if (err) {
            goto out;
        }
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestNetworkInterface(Visitor *v, GuestNetworkInterface **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestNetworkInterface", name, sizeof(GuestNetworkInterface), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestNetworkInterface_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_GuestNetworkInterfaceList(Visitor *v, GuestNetworkInterfaceList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev, &err)) != NULL;
         prev = &i) {
        GuestNetworkInterfaceList *native_i = (GuestNetworkInterfaceList *)i;
        visit_type_GuestNetworkInterface(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v, &err);
out:
    error_propagate(errp, err);
}

static void visit_type_GuestPCIAddress_fields(Visitor *v, GuestPCIAddress **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->domain, "domain", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->bus, "bus", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->slot, "slot", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->function, "function", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_GuestPCIAddress(Visitor *v, GuestPCIAddress **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "GuestPCIAddress", name, sizeof(GuestPCIAddress), &err);
    if (!err) {
        if (*obj) {
            visit_type_GuestPCIAddress_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}
