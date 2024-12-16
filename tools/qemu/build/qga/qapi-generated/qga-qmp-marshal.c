/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QMP->QAPI command dispatch
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
#include "qemu/module.h"
#include "qapi/qmp/types.h"
#include "qapi/qmp/dispatch.h"
#include "qapi/visitor.h"
#include "qapi/qmp-output-visitor.h"
#include "qapi/qmp-input-visitor.h"
#include "qapi/dealloc-visitor.h"
#include "qga-qapi-types.h"
#include "qga-qapi-visit.h"
#include "qga-qmp-commands.h"


static void qmp_marshal_output_GuestExec(GuestExec *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestExec(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestExec(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_exec(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestExec *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *path = NULL;
    bool has_arg = false;
    strList *arg = NULL;
    bool has_env = false;
    strList *env = NULL;
    bool has_input_data = false;
    char *input_data = NULL;
    bool has_capture_output = false;
    bool capture_output = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &path, "path", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_arg, "arg", &err);
    if (err) {
        goto out;
    }
    if (has_arg) {
        visit_type_strList(v, &arg, "arg", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_env, "env", &err);
    if (err) {
        goto out;
    }
    if (has_env) {
        visit_type_strList(v, &env, "env", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_input_data, "input-data", &err);
    if (err) {
        goto out;
    }
    if (has_input_data) {
        visit_type_str(v, &input_data, "input-data", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_capture_output, "capture-output", &err);
    if (err) {
        goto out;
    }
    if (has_capture_output) {
        visit_type_bool(v, &capture_output, "capture-output", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_guest_exec(path, has_arg, arg, has_env, env, has_input_data, input_data, has_capture_output, capture_output, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestExec(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &path, "path", NULL);
    visit_optional(v, &has_arg, "arg", NULL);
    if (has_arg) {
        visit_type_strList(v, &arg, "arg", NULL);
    }
    visit_optional(v, &has_env, "env", NULL);
    if (has_env) {
        visit_type_strList(v, &env, "env", NULL);
    }
    visit_optional(v, &has_input_data, "input-data", NULL);
    if (has_input_data) {
        visit_type_str(v, &input_data, "input-data", NULL);
    }
    visit_optional(v, &has_capture_output, "capture-output", NULL);
    if (has_capture_output) {
        visit_type_bool(v, &capture_output, "capture-output", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_GuestExecStatus(GuestExecStatus *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestExecStatus(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestExecStatus(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_exec_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestExecStatus *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t pid = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &pid, "pid", &err);
    if (err) {
        goto out;
    }

    retval = qmp_guest_exec_status(pid, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestExecStatus(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &pid, "pid", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_file_close(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t handle = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &handle, "handle", &err);
    if (err) {
        goto out;
    }

    qmp_guest_file_close(handle, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &handle, "handle", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_file_flush(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t handle = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &handle, "handle", &err);
    if (err) {
        goto out;
    }

    qmp_guest_file_flush(handle, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &handle, "handle", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_int(int64_t ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_int(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_file_open(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *path = NULL;
    bool has_mode = false;
    char *mode = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &path, "path", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_mode, "mode", &err);
    if (err) {
        goto out;
    }
    if (has_mode) {
        visit_type_str(v, &mode, "mode", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_guest_file_open(path, has_mode, mode, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &path, "path", NULL);
    visit_optional(v, &has_mode, "mode", NULL);
    if (has_mode) {
        visit_type_str(v, &mode, "mode", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_GuestFileRead(GuestFileRead *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestFileRead(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestFileRead(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_file_read(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFileRead *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t handle = 0;
    bool has_count = false;
    int64_t count = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &handle, "handle", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_count, "count", &err);
    if (err) {
        goto out;
    }
    if (has_count) {
        visit_type_int(v, &count, "count", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_guest_file_read(handle, has_count, count, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFileRead(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &handle, "handle", NULL);
    visit_optional(v, &has_count, "count", NULL);
    if (has_count) {
        visit_type_int(v, &count, "count", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_GuestFileSeek(GuestFileSeek *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestFileSeek(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestFileSeek(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_file_seek(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFileSeek *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t handle = 0;
    int64_t offset = 0;
    int64_t whence = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &handle, "handle", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &offset, "offset", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &whence, "whence", &err);
    if (err) {
        goto out;
    }

    retval = qmp_guest_file_seek(handle, offset, whence, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFileSeek(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &handle, "handle", NULL);
    visit_type_int(v, &offset, "offset", NULL);
    visit_type_int(v, &whence, "whence", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_GuestFileWrite(GuestFileWrite *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestFileWrite(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestFileWrite(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_file_write(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFileWrite *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t handle = 0;
    char *buf_b64 = NULL;
    bool has_count = false;
    int64_t count = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &handle, "handle", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &buf_b64, "buf-b64", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_count, "count", &err);
    if (err) {
        goto out;
    }
    if (has_count) {
        visit_type_int(v, &count, "count", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_guest_file_write(handle, buf_b64, has_count, count, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFileWrite(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &handle, "handle", NULL);
    visit_type_str(v, &buf_b64, "buf-b64", NULL);
    visit_optional(v, &has_count, "count", NULL);
    if (has_count) {
        visit_type_int(v, &count, "count", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_fsfreeze_freeze(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;

    (void)args;

    retval = qmp_guest_fsfreeze_freeze(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_guest_fsfreeze_freeze_list(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_mountpoints = false;
    strList *mountpoints = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_mountpoints, "mountpoints", &err);
    if (err) {
        goto out;
    }
    if (has_mountpoints) {
        visit_type_strList(v, &mountpoints, "mountpoints", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_guest_fsfreeze_freeze_list(has_mountpoints, mountpoints, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_mountpoints, "mountpoints", NULL);
    if (has_mountpoints) {
        visit_type_strList(v, &mountpoints, "mountpoints", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_GuestFsfreezeStatus(GuestFsfreezeStatus ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestFsfreezeStatus(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestFsfreezeStatus(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_fsfreeze_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFsfreezeStatus retval;

    (void)args;

    retval = qmp_guest_fsfreeze_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFsfreezeStatus(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_guest_fsfreeze_thaw(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;

    (void)args;

    retval = qmp_guest_fsfreeze_thaw(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestFilesystemTrimResponse(GuestFilesystemTrimResponse *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestFilesystemTrimResponse(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestFilesystemTrimResponse(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_fstrim(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFilesystemTrimResponse *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_minimum = false;
    int64_t minimum = 0;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_minimum, "minimum", &err);
    if (err) {
        goto out;
    }
    if (has_minimum) {
        visit_type_int(v, &minimum, "minimum", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_guest_fstrim(has_minimum, minimum, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFilesystemTrimResponse(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_minimum, "minimum", NULL);
    if (has_minimum) {
        visit_type_int(v, &minimum, "minimum", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_GuestFilesystemInfoList(GuestFilesystemInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestFilesystemInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestFilesystemInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_get_fsinfo(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestFilesystemInfoList *retval;

    (void)args;

    retval = qmp_guest_get_fsinfo(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestFilesystemInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestMemoryBlockInfo(GuestMemoryBlockInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestMemoryBlockInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestMemoryBlockInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_get_memory_block_info(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestMemoryBlockInfo *retval;

    (void)args;

    retval = qmp_guest_get_memory_block_info(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestMemoryBlockInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestMemoryBlockList(GuestMemoryBlockList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestMemoryBlockList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestMemoryBlockList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_get_memory_blocks(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestMemoryBlockList *retval;

    (void)args;

    retval = qmp_guest_get_memory_blocks(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestMemoryBlockList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_guest_get_time(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;

    (void)args;

    retval = qmp_guest_get_time(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestLogicalProcessorList(GuestLogicalProcessorList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestLogicalProcessorList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestLogicalProcessorList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_get_vcpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestLogicalProcessorList *retval;

    (void)args;

    retval = qmp_guest_get_vcpus(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestLogicalProcessorList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestAgentInfo(GuestAgentInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestAgentInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestAgentInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_info(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestAgentInfo *retval;

    (void)args;

    retval = qmp_guest_info(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestAgentInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestNetworkInterfaceList(GuestNetworkInterfaceList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestNetworkInterfaceList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestNetworkInterfaceList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_network_get_interfaces(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestNetworkInterfaceList *retval;

    (void)args;

    retval = qmp_guest_network_get_interfaces(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestNetworkInterfaceList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_guest_ping(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_guest_ping(&err);
    error_propagate(errp, err);
}

static void qmp_marshal_output_GuestMemoryBlockResponseList(GuestMemoryBlockResponseList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_GuestMemoryBlockResponseList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestMemoryBlockResponseList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_set_memory_blocks(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    GuestMemoryBlockResponseList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    GuestMemoryBlockList *mem_blks = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_GuestMemoryBlockList(v, &mem_blks, "mem-blks", &err);
    if (err) {
        goto out;
    }

    retval = qmp_guest_set_memory_blocks(mem_blks, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_GuestMemoryBlockResponseList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestMemoryBlockList(v, &mem_blks, "mem-blks", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_set_time(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_time = false;
    int64_t time = 0;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_time, "time", &err);
    if (err) {
        goto out;
    }
    if (has_time) {
        visit_type_int(v, &time, "time", &err);
        if (err) {
            goto out;
        }
    }

    qmp_guest_set_time(has_time, time, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_time, "time", NULL);
    if (has_time) {
        visit_type_int(v, &time, "time", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_set_user_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *username = NULL;
    char *password = NULL;
    bool crypted = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &username, "username", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &password, "password", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &crypted, "crypted", &err);
    if (err) {
        goto out;
    }

    qmp_guest_set_user_password(username, password, crypted, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &username, "username", NULL);
    visit_type_str(v, &password, "password", NULL);
    visit_type_bool(v, &crypted, "crypted", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_set_vcpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    GuestLogicalProcessorList *vcpus = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_GuestLogicalProcessorList(v, &vcpus, "vcpus", &err);
    if (err) {
        goto out;
    }

    retval = qmp_guest_set_vcpus(vcpus, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_GuestLogicalProcessorList(v, &vcpus, "vcpus", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_shutdown(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_mode = false;
    char *mode = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_mode, "mode", &err);
    if (err) {
        goto out;
    }
    if (has_mode) {
        visit_type_str(v, &mode, "mode", &err);
        if (err) {
            goto out;
        }
    }

    qmp_guest_shutdown(has_mode, mode, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_mode, "mode", NULL);
    if (has_mode) {
        visit_type_str(v, &mode, "mode", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_suspend_disk(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_guest_suspend_disk(&err);
    error_propagate(errp, err);
}

static void qmp_marshal_guest_suspend_hybrid(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_guest_suspend_hybrid(&err);
    error_propagate(errp, err);
}

static void qmp_marshal_guest_suspend_ram(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_guest_suspend_ram(&err);
    error_propagate(errp, err);
}

static void qmp_marshal_guest_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t id = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    retval = qmp_guest_sync(id, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_guest_sync_delimited(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t id = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    retval = qmp_guest_sync_delimited(id, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_init_marshal(void)
{
    qmp_register_command("guest-exec", qmp_marshal_guest_exec, QCO_NO_OPTIONS);
    qmp_register_command("guest-exec-status", qmp_marshal_guest_exec_status, QCO_NO_OPTIONS);
    qmp_register_command("guest-file-close", qmp_marshal_guest_file_close, QCO_NO_OPTIONS);
    qmp_register_command("guest-file-flush", qmp_marshal_guest_file_flush, QCO_NO_OPTIONS);
    qmp_register_command("guest-file-open", qmp_marshal_guest_file_open, QCO_NO_OPTIONS);
    qmp_register_command("guest-file-read", qmp_marshal_guest_file_read, QCO_NO_OPTIONS);
    qmp_register_command("guest-file-seek", qmp_marshal_guest_file_seek, QCO_NO_OPTIONS);
    qmp_register_command("guest-file-write", qmp_marshal_guest_file_write, QCO_NO_OPTIONS);
    qmp_register_command("guest-fsfreeze-freeze", qmp_marshal_guest_fsfreeze_freeze, QCO_NO_OPTIONS);
    qmp_register_command("guest-fsfreeze-freeze-list", qmp_marshal_guest_fsfreeze_freeze_list, QCO_NO_OPTIONS);
    qmp_register_command("guest-fsfreeze-status", qmp_marshal_guest_fsfreeze_status, QCO_NO_OPTIONS);
    qmp_register_command("guest-fsfreeze-thaw", qmp_marshal_guest_fsfreeze_thaw, QCO_NO_OPTIONS);
    qmp_register_command("guest-fstrim", qmp_marshal_guest_fstrim, QCO_NO_OPTIONS);
    qmp_register_command("guest-get-fsinfo", qmp_marshal_guest_get_fsinfo, QCO_NO_OPTIONS);
    qmp_register_command("guest-get-memory-block-info", qmp_marshal_guest_get_memory_block_info, QCO_NO_OPTIONS);
    qmp_register_command("guest-get-memory-blocks", qmp_marshal_guest_get_memory_blocks, QCO_NO_OPTIONS);
    qmp_register_command("guest-get-time", qmp_marshal_guest_get_time, QCO_NO_OPTIONS);
    qmp_register_command("guest-get-vcpus", qmp_marshal_guest_get_vcpus, QCO_NO_OPTIONS);
    qmp_register_command("guest-info", qmp_marshal_guest_info, QCO_NO_OPTIONS);
    qmp_register_command("guest-network-get-interfaces", qmp_marshal_guest_network_get_interfaces, QCO_NO_OPTIONS);
    qmp_register_command("guest-ping", qmp_marshal_guest_ping, QCO_NO_OPTIONS);
    qmp_register_command("guest-set-memory-blocks", qmp_marshal_guest_set_memory_blocks, QCO_NO_OPTIONS);
    qmp_register_command("guest-set-time", qmp_marshal_guest_set_time, QCO_NO_OPTIONS);
    qmp_register_command("guest-set-user-password", qmp_marshal_guest_set_user_password, QCO_NO_OPTIONS);
    qmp_register_command("guest-set-vcpus", qmp_marshal_guest_set_vcpus, QCO_NO_OPTIONS);
    qmp_register_command("guest-shutdown", qmp_marshal_guest_shutdown, QCO_NO_SUCCESS_RESP);
    qmp_register_command("guest-suspend-disk", qmp_marshal_guest_suspend_disk, QCO_NO_SUCCESS_RESP);
    qmp_register_command("guest-suspend-hybrid", qmp_marshal_guest_suspend_hybrid, QCO_NO_SUCCESS_RESP);
    qmp_register_command("guest-suspend-ram", qmp_marshal_guest_suspend_ram, QCO_NO_SUCCESS_RESP);
    qmp_register_command("guest-sync", qmp_marshal_guest_sync, QCO_NO_OPTIONS);
    qmp_register_command("guest-sync-delimited", qmp_marshal_guest_sync_delimited, QCO_NO_OPTIONS);
}

qapi_init(qmp_init_marshal);
