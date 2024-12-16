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
#include "qapi-types.h"
#include "qapi-visit.h"
#include "qmp-commands.h"


static void qmp_marshal_output_AddfdInfo(AddfdInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_AddfdInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_AddfdInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_add_fd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    AddfdInfo *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_fdset_id = false;
    int64_t fdset_id = 0;
    bool has_opaque = false;
    char *opaque = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_fdset_id, "fdset-id", &err);
    if (err) {
        goto out;
    }
    if (has_fdset_id) {
        visit_type_int(v, &fdset_id, "fdset-id", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_opaque, "opaque", &err);
    if (err) {
        goto out;
    }
    if (has_opaque) {
        visit_type_str(v, &opaque, "opaque", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_add_fd(has_fdset_id, fdset_id, has_opaque, opaque, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_AddfdInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_fdset_id, "fdset-id", NULL);
    if (has_fdset_id) {
        visit_type_int(v, &fdset_id, "fdset-id", NULL);
    }
    visit_optional(v, &has_opaque, "opaque", NULL);
    if (has_opaque) {
        visit_type_str(v, &opaque, "opaque", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_add_client(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *protocol = NULL;
    char *fdname = NULL;
    bool has_skipauth = false;
    bool skipauth = false;
    bool has_tls = false;
    bool tls = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &protocol, "protocol", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &fdname, "fdname", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_skipauth, "skipauth", &err);
    if (err) {
        goto out;
    }
    if (has_skipauth) {
        visit_type_bool(v, &skipauth, "skipauth", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_tls, "tls", &err);
    if (err) {
        goto out;
    }
    if (has_tls) {
        visit_type_bool(v, &tls, "tls", &err);
        if (err) {
            goto out;
        }
    }

    qmp_add_client(protocol, fdname, has_skipauth, skipauth, has_tls, tls, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &protocol, "protocol", NULL);
    visit_type_str(v, &fdname, "fdname", NULL);
    visit_optional(v, &has_skipauth, "skipauth", NULL);
    if (has_skipauth) {
        visit_type_bool(v, &skipauth, "skipauth", NULL);
    }
    visit_optional(v, &has_tls, "tls", NULL);
    if (has_tls) {
        visit_type_bool(v, &tls, "tls", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_balloon(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t value = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &value, "value", &err);
    if (err) {
        goto out;
    }

    qmp_balloon(value, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &value, "value", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_commit(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_base = false;
    char *base = NULL;
    bool has_top = false;
    char *top = NULL;
    bool has_backing_file = false;
    char *backing_file = NULL;
    bool has_speed = false;
    int64_t speed = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_base, "base", &err);
    if (err) {
        goto out;
    }
    if (has_base) {
        visit_type_str(v, &base, "base", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_top, "top", &err);
    if (err) {
        goto out;
    }
    if (has_top) {
        visit_type_str(v, &top, "top", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_backing_file, "backing-file", &err);
    if (err) {
        goto out;
    }
    if (has_backing_file) {
        visit_type_str(v, &backing_file, "backing-file", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_speed, "speed", &err);
    if (err) {
        goto out;
    }
    if (has_speed) {
        visit_type_int(v, &speed, "speed", &err);
        if (err) {
            goto out;
        }
    }

    qmp_block_commit(device, has_base, base, has_top, top, has_backing_file, backing_file, has_speed, speed, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_base, "base", NULL);
    if (has_base) {
        visit_type_str(v, &base, "base", NULL);
    }
    visit_optional(v, &has_top, "top", NULL);
    if (has_top) {
        visit_type_str(v, &top, "top", NULL);
    }
    visit_optional(v, &has_backing_file, "backing-file", NULL);
    if (has_backing_file) {
        visit_type_str(v, &backing_file, "backing-file", NULL);
    }
    visit_optional(v, &has_speed, "speed", NULL);
    if (has_speed) {
        visit_type_int(v, &speed, "speed", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_dirty_bitmap_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *node = NULL;
    char *name = NULL;
    bool has_granularity = false;
    uint32_t granularity = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &node, "node", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_granularity, "granularity", &err);
    if (err) {
        goto out;
    }
    if (has_granularity) {
        visit_type_uint32(v, &granularity, "granularity", &err);
        if (err) {
            goto out;
        }
    }

    qmp_block_dirty_bitmap_add(node, name, has_granularity, granularity, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &node, "node", NULL);
    visit_type_str(v, &name, "name", NULL);
    visit_optional(v, &has_granularity, "granularity", NULL);
    if (has_granularity) {
        visit_type_uint32(v, &granularity, "granularity", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_dirty_bitmap_clear(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *node = NULL;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &node, "node", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }

    qmp_block_dirty_bitmap_clear(node, name, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &node, "node", NULL);
    visit_type_str(v, &name, "name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_dirty_bitmap_remove(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *node = NULL;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &node, "node", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }

    qmp_block_dirty_bitmap_remove(node, name, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &node, "node", NULL);
    visit_type_str(v, &name, "name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_job_cancel(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_force = false;
    bool force = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_force, "force", &err);
    if (err) {
        goto out;
    }
    if (has_force) {
        visit_type_bool(v, &force, "force", &err);
        if (err) {
            goto out;
        }
    }

    qmp_block_job_cancel(device, has_force, force, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_force, "force", NULL);
    if (has_force) {
        visit_type_bool(v, &force, "force", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_job_complete(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }

    qmp_block_job_complete(device, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_job_pause(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }

    qmp_block_job_pause(device, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_job_resume(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }

    qmp_block_job_resume(device, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_job_set_speed(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    int64_t speed = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &speed, "speed", &err);
    if (err) {
        goto out;
    }

    qmp_block_job_set_speed(device, speed, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_int(v, &speed, "speed", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_set_write_threshold(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *node_name = NULL;
    uint64_t write_threshold = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &node_name, "node-name", &err);
    if (err) {
        goto out;
    }
    visit_type_uint64(v, &write_threshold, "write-threshold", &err);
    if (err) {
        goto out;
    }

    qmp_block_set_write_threshold(node_name, write_threshold, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &node_name, "node-name", NULL);
    visit_type_uint64(v, &write_threshold, "write-threshold", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_stream(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_base = false;
    char *base = NULL;
    bool has_backing_file = false;
    char *backing_file = NULL;
    bool has_speed = false;
    int64_t speed = 0;
    bool has_on_error = false;
    BlockdevOnError on_error = BLOCKDEV_ON_ERROR_REPORT;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_base, "base", &err);
    if (err) {
        goto out;
    }
    if (has_base) {
        visit_type_str(v, &base, "base", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_backing_file, "backing-file", &err);
    if (err) {
        goto out;
    }
    if (has_backing_file) {
        visit_type_str(v, &backing_file, "backing-file", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_speed, "speed", &err);
    if (err) {
        goto out;
    }
    if (has_speed) {
        visit_type_int(v, &speed, "speed", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_error, "on-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_error) {
        visit_type_BlockdevOnError(v, &on_error, "on-error", &err);
        if (err) {
            goto out;
        }
    }

    qmp_block_stream(device, has_base, base, has_backing_file, backing_file, has_speed, speed, has_on_error, on_error, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_base, "base", NULL);
    if (has_base) {
        visit_type_str(v, &base, "base", NULL);
    }
    visit_optional(v, &has_backing_file, "backing-file", NULL);
    if (has_backing_file) {
        visit_type_str(v, &backing_file, "backing-file", NULL);
    }
    visit_optional(v, &has_speed, "speed", NULL);
    if (has_speed) {
        visit_type_int(v, &speed, "speed", NULL);
    }
    visit_optional(v, &has_on_error, "on-error", NULL);
    if (has_on_error) {
        visit_type_BlockdevOnError(v, &on_error, "on-error", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_passwd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_device = false;
    char *device = NULL;
    bool has_node_name = false;
    char *node_name = NULL;
    char *password = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_device, "device", &err);
    if (err) {
        goto out;
    }
    if (has_device) {
        visit_type_str(v, &device, "device", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_node_name, "node-name", &err);
    if (err) {
        goto out;
    }
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, &password, "password", &err);
    if (err) {
        goto out;
    }

    qmp_block_passwd(has_device, device, has_node_name, node_name, password, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_device, "device", NULL);
    if (has_device) {
        visit_type_str(v, &device, "device", NULL);
    }
    visit_optional(v, &has_node_name, "node-name", NULL);
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", NULL);
    }
    visit_type_str(v, &password, "password", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_resize(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_device = false;
    char *device = NULL;
    bool has_node_name = false;
    char *node_name = NULL;
    int64_t size = 0;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_device, "device", &err);
    if (err) {
        goto out;
    }
    if (has_device) {
        visit_type_str(v, &device, "device", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_node_name, "node-name", &err);
    if (err) {
        goto out;
    }
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_int(v, &size, "size", &err);
    if (err) {
        goto out;
    }

    qmp_block_resize(has_device, device, has_node_name, node_name, size, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_device, "device", NULL);
    if (has_device) {
        visit_type_str(v, &device, "device", NULL);
    }
    visit_optional(v, &has_node_name, "node-name", NULL);
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", NULL);
    }
    visit_type_int(v, &size, "size", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_block_set_io_throttle(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    int64_t bps = 0;
    int64_t bps_rd = 0;
    int64_t bps_wr = 0;
    int64_t iops = 0;
    int64_t iops_rd = 0;
    int64_t iops_wr = 0;
    bool has_bps_max = false;
    int64_t bps_max = 0;
    bool has_bps_rd_max = false;
    int64_t bps_rd_max = 0;
    bool has_bps_wr_max = false;
    int64_t bps_wr_max = 0;
    bool has_iops_max = false;
    int64_t iops_max = 0;
    bool has_iops_rd_max = false;
    int64_t iops_rd_max = 0;
    bool has_iops_wr_max = false;
    int64_t iops_wr_max = 0;
    bool has_iops_size = false;
    int64_t iops_size = 0;
    bool has_group = false;
    char *group = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &bps, "bps", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &bps_rd, "bps_rd", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &bps_wr, "bps_wr", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &iops, "iops", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &iops_rd, "iops_rd", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &iops_wr, "iops_wr", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_bps_max, "bps_max", &err);
    if (err) {
        goto out;
    }
    if (has_bps_max) {
        visit_type_int(v, &bps_max, "bps_max", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_bps_rd_max, "bps_rd_max", &err);
    if (err) {
        goto out;
    }
    if (has_bps_rd_max) {
        visit_type_int(v, &bps_rd_max, "bps_rd_max", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_bps_wr_max, "bps_wr_max", &err);
    if (err) {
        goto out;
    }
    if (has_bps_wr_max) {
        visit_type_int(v, &bps_wr_max, "bps_wr_max", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_iops_max, "iops_max", &err);
    if (err) {
        goto out;
    }
    if (has_iops_max) {
        visit_type_int(v, &iops_max, "iops_max", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_iops_rd_max, "iops_rd_max", &err);
    if (err) {
        goto out;
    }
    if (has_iops_rd_max) {
        visit_type_int(v, &iops_rd_max, "iops_rd_max", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_iops_wr_max, "iops_wr_max", &err);
    if (err) {
        goto out;
    }
    if (has_iops_wr_max) {
        visit_type_int(v, &iops_wr_max, "iops_wr_max", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_iops_size, "iops_size", &err);
    if (err) {
        goto out;
    }
    if (has_iops_size) {
        visit_type_int(v, &iops_size, "iops_size", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_group, "group", &err);
    if (err) {
        goto out;
    }
    if (has_group) {
        visit_type_str(v, &group, "group", &err);
        if (err) {
            goto out;
        }
    }

    qmp_block_set_io_throttle(device, bps, bps_rd, bps_wr, iops, iops_rd, iops_wr, has_bps_max, bps_max, has_bps_rd_max, bps_rd_max, has_bps_wr_max, bps_wr_max, has_iops_max, iops_max, has_iops_rd_max, iops_rd_max, has_iops_wr_max, iops_wr_max, has_iops_size, iops_size, has_group, group, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_int(v, &bps, "bps", NULL);
    visit_type_int(v, &bps_rd, "bps_rd", NULL);
    visit_type_int(v, &bps_wr, "bps_wr", NULL);
    visit_type_int(v, &iops, "iops", NULL);
    visit_type_int(v, &iops_rd, "iops_rd", NULL);
    visit_type_int(v, &iops_wr, "iops_wr", NULL);
    visit_optional(v, &has_bps_max, "bps_max", NULL);
    if (has_bps_max) {
        visit_type_int(v, &bps_max, "bps_max", NULL);
    }
    visit_optional(v, &has_bps_rd_max, "bps_rd_max", NULL);
    if (has_bps_rd_max) {
        visit_type_int(v, &bps_rd_max, "bps_rd_max", NULL);
    }
    visit_optional(v, &has_bps_wr_max, "bps_wr_max", NULL);
    if (has_bps_wr_max) {
        visit_type_int(v, &bps_wr_max, "bps_wr_max", NULL);
    }
    visit_optional(v, &has_iops_max, "iops_max", NULL);
    if (has_iops_max) {
        visit_type_int(v, &iops_max, "iops_max", NULL);
    }
    visit_optional(v, &has_iops_rd_max, "iops_rd_max", NULL);
    if (has_iops_rd_max) {
        visit_type_int(v, &iops_rd_max, "iops_rd_max", NULL);
    }
    visit_optional(v, &has_iops_wr_max, "iops_wr_max", NULL);
    if (has_iops_wr_max) {
        visit_type_int(v, &iops_wr_max, "iops_wr_max", NULL);
    }
    visit_optional(v, &has_iops_size, "iops_size", NULL);
    if (has_iops_size) {
        visit_type_int(v, &iops_size, "iops_size", NULL);
    }
    visit_optional(v, &has_group, "group", NULL);
    if (has_group) {
        visit_type_str(v, &group, "group", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    BlockdevOptions *options = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_BlockdevOptions(v, &options, "options", &err);
    if (err) {
        goto out;
    }

    qmp_blockdev_add(options, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_BlockdevOptions(v, &options, "options", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_backup(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *target = NULL;
    MirrorSyncMode sync = MIRROR_SYNC_MODE_TOP;
    bool has_speed = false;
    int64_t speed = 0;
    bool has_on_source_error = false;
    BlockdevOnError on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    bool has_on_target_error = false;
    BlockdevOnError on_target_error = BLOCKDEV_ON_ERROR_REPORT;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &target, "target", &err);
    if (err) {
        goto out;
    }
    visit_type_MirrorSyncMode(v, &sync, "sync", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_speed, "speed", &err);
    if (err) {
        goto out;
    }
    if (has_speed) {
        visit_type_int(v, &speed, "speed", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_source_error, "on-source-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_source_error) {
        visit_type_BlockdevOnError(v, &on_source_error, "on-source-error", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_target_error, "on-target-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_target_error) {
        visit_type_BlockdevOnError(v, &on_target_error, "on-target-error", &err);
        if (err) {
            goto out;
        }
    }

    qmp_blockdev_backup(device, target, sync, has_speed, speed, has_on_source_error, on_source_error, has_on_target_error, on_target_error, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &target, "target", NULL);
    visit_type_MirrorSyncMode(v, &sync, "sync", NULL);
    visit_optional(v, &has_speed, "speed", NULL);
    if (has_speed) {
        visit_type_int(v, &speed, "speed", NULL);
    }
    visit_optional(v, &has_on_source_error, "on-source-error", NULL);
    if (has_on_source_error) {
        visit_type_BlockdevOnError(v, &on_source_error, "on-source-error", NULL);
    }
    visit_optional(v, &has_on_target_error, "on-target-error", NULL);
    if (has_on_target_error) {
        visit_type_BlockdevOnError(v, &on_target_error, "on-target-error", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_change_medium(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *filename = NULL;
    bool has_format = false;
    char *format = NULL;
    bool has_read_only_mode = false;
    BlockdevChangeReadOnlyMode read_only_mode = BLOCKDEV_CHANGE_READ_ONLY_MODE_RETAIN;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &filename, "filename", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_str(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_read_only_mode, "read-only-mode", &err);
    if (err) {
        goto out;
    }
    if (has_read_only_mode) {
        visit_type_BlockdevChangeReadOnlyMode(v, &read_only_mode, "read-only-mode", &err);
        if (err) {
            goto out;
        }
    }

    qmp_blockdev_change_medium(device, filename, has_format, format, has_read_only_mode, read_only_mode, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &filename, "filename", NULL);
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_str(v, &format, "format", NULL);
    }
    visit_optional(v, &has_read_only_mode, "read-only-mode", NULL);
    if (has_read_only_mode) {
        visit_type_BlockdevChangeReadOnlyMode(v, &read_only_mode, "read-only-mode", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_close_tray(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }

    qmp_blockdev_close_tray(device, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_open_tray(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_force = false;
    bool force = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_force, "force", &err);
    if (err) {
        goto out;
    }
    if (has_force) {
        visit_type_bool(v, &force, "force", &err);
        if (err) {
            goto out;
        }
    }

    qmp_blockdev_open_tray(device, has_force, force, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_force, "force", NULL);
    if (has_force) {
        visit_type_bool(v, &force, "force", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_snapshot(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *node = NULL;
    char *overlay = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &node, "node", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &overlay, "overlay", &err);
    if (err) {
        goto out;
    }

    qmp_blockdev_snapshot(node, overlay, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &node, "node", NULL);
    visit_type_str(v, &overlay, "overlay", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_SnapshotInfo(SnapshotInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_SnapshotInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_SnapshotInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_snapshot_delete_internal_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    SnapshotInfo *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_id = false;
    char *id = NULL;
    bool has_name = false;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_id, "id", &err);
    if (err) {
        goto out;
    }
    if (has_id) {
        visit_type_str(v, &id, "id", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_name, "name", &err);
    if (err) {
        goto out;
    }
    if (has_name) {
        visit_type_str(v, &name, "name", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_blockdev_snapshot_delete_internal_sync(device, has_id, id, has_name, name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_SnapshotInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_id, "id", NULL);
    if (has_id) {
        visit_type_str(v, &id, "id", NULL);
    }
    visit_optional(v, &has_name, "name", NULL);
    if (has_name) {
        visit_type_str(v, &name, "name", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_snapshot_internal_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }

    qmp_blockdev_snapshot_internal_sync(device, name, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &name, "name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_blockdev_snapshot_sync(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_device = false;
    char *device = NULL;
    bool has_node_name = false;
    char *node_name = NULL;
    char *snapshot_file = NULL;
    bool has_snapshot_node_name = false;
    char *snapshot_node_name = NULL;
    bool has_format = false;
    char *format = NULL;
    bool has_mode = false;
    NewImageMode mode = NEW_IMAGE_MODE_EXISTING;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_device, "device", &err);
    if (err) {
        goto out;
    }
    if (has_device) {
        visit_type_str(v, &device, "device", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_node_name, "node-name", &err);
    if (err) {
        goto out;
    }
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_str(v, &snapshot_file, "snapshot-file", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_snapshot_node_name, "snapshot-node-name", &err);
    if (err) {
        goto out;
    }
    if (has_snapshot_node_name) {
        visit_type_str(v, &snapshot_node_name, "snapshot-node-name", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_str(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_mode, "mode", &err);
    if (err) {
        goto out;
    }
    if (has_mode) {
        visit_type_NewImageMode(v, &mode, "mode", &err);
        if (err) {
            goto out;
        }
    }

    qmp_blockdev_snapshot_sync(has_device, device, has_node_name, node_name, snapshot_file, has_snapshot_node_name, snapshot_node_name, has_format, format, has_mode, mode, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_device, "device", NULL);
    if (has_device) {
        visit_type_str(v, &device, "device", NULL);
    }
    visit_optional(v, &has_node_name, "node-name", NULL);
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", NULL);
    }
    visit_type_str(v, &snapshot_file, "snapshot-file", NULL);
    visit_optional(v, &has_snapshot_node_name, "snapshot-node-name", NULL);
    if (has_snapshot_node_name) {
        visit_type_str(v, &snapshot_node_name, "snapshot-node-name", NULL);
    }
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_str(v, &format, "format", NULL);
    }
    visit_optional(v, &has_mode, "mode", NULL);
    if (has_mode) {
        visit_type_NewImageMode(v, &mode, "mode", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_change(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *target = NULL;
    bool has_arg = false;
    char *arg = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &target, "target", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_arg, "arg", &err);
    if (err) {
        goto out;
    }
    if (has_arg) {
        visit_type_str(v, &arg, "arg", &err);
        if (err) {
            goto out;
        }
    }

    qmp_change(device, target, has_arg, arg, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &target, "target", NULL);
    visit_optional(v, &has_arg, "arg", NULL);
    if (has_arg) {
        visit_type_str(v, &arg, "arg", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_change_backing_file(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *image_node_name = NULL;
    char *backing_file = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &image_node_name, "image-node-name", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &backing_file, "backing-file", &err);
    if (err) {
        goto out;
    }

    qmp_change_backing_file(device, image_node_name, backing_file, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &image_node_name, "image-node-name", NULL);
    visit_type_str(v, &backing_file, "backing-file", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_change_vnc_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *password = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &password, "password", &err);
    if (err) {
        goto out;
    }

    qmp_change_vnc_password(password, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &password, "password", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_ChardevReturn(ChardevReturn *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_ChardevReturn(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_ChardevReturn(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_chardev_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ChardevReturn *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *id = NULL;
    ChardevBackend *backend = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &id, "id", &err);
    if (err) {
        goto out;
    }
    visit_type_ChardevBackend(v, &backend, "backend", &err);
    if (err) {
        goto out;
    }

    retval = qmp_chardev_add(id, backend, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ChardevReturn(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &id, "id", NULL);
    visit_type_ChardevBackend(v, &backend, "backend", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_chardev_remove(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *id = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    qmp_chardev_remove(id, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_client_migrate_info(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *protocol = NULL;
    char *hostname = NULL;
    bool has_port = false;
    int64_t port = 0;
    bool has_tls_port = false;
    int64_t tls_port = 0;
    bool has_cert_subject = false;
    char *cert_subject = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &protocol, "protocol", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &hostname, "hostname", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_port, "port", &err);
    if (err) {
        goto out;
    }
    if (has_port) {
        visit_type_int(v, &port, "port", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_tls_port, "tls-port", &err);
    if (err) {
        goto out;
    }
    if (has_tls_port) {
        visit_type_int(v, &tls_port, "tls-port", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_cert_subject, "cert-subject", &err);
    if (err) {
        goto out;
    }
    if (has_cert_subject) {
        visit_type_str(v, &cert_subject, "cert-subject", &err);
        if (err) {
            goto out;
        }
    }

    qmp_client_migrate_info(protocol, hostname, has_port, port, has_tls_port, tls_port, has_cert_subject, cert_subject, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &protocol, "protocol", NULL);
    visit_type_str(v, &hostname, "hostname", NULL);
    visit_optional(v, &has_port, "port", NULL);
    if (has_port) {
        visit_type_int(v, &port, "port", NULL);
    }
    visit_optional(v, &has_tls_port, "tls-port", NULL);
    if (has_tls_port) {
        visit_type_int(v, &tls_port, "tls-port", NULL);
    }
    visit_optional(v, &has_cert_subject, "cert-subject", NULL);
    if (has_cert_subject) {
        visit_type_str(v, &cert_subject, "cert-subject", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_closefd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *fdname = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &fdname, "fdname", &err);
    if (err) {
        goto out;
    }

    qmp_closefd(fdname, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &fdname, "fdname", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_cont(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_cont(&err);
    error_propagate(errp, err);
}

void qmp_marshal_cpu(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t index = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &index, "index", &err);
    if (err) {
        goto out;
    }

    qmp_cpu(index, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &index, "index", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_cpu_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t id = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    qmp_cpu_add(id, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_DevicePropertyInfoList(DevicePropertyInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_DevicePropertyInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_DevicePropertyInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_device_list_properties(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    DevicePropertyInfoList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *q_typename = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &q_typename, "typename", &err);
    if (err) {
        goto out;
    }

    retval = qmp_device_list_properties(q_typename, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_DevicePropertyInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &q_typename, "typename", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_device_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *id = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    qmp_device_del(id, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_drive_backup(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *target = NULL;
    bool has_format = false;
    char *format = NULL;
    MirrorSyncMode sync = MIRROR_SYNC_MODE_TOP;
    bool has_mode = false;
    NewImageMode mode = NEW_IMAGE_MODE_EXISTING;
    bool has_speed = false;
    int64_t speed = 0;
    bool has_bitmap = false;
    char *bitmap = NULL;
    bool has_on_source_error = false;
    BlockdevOnError on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    bool has_on_target_error = false;
    BlockdevOnError on_target_error = BLOCKDEV_ON_ERROR_REPORT;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &target, "target", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_str(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_MirrorSyncMode(v, &sync, "sync", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_mode, "mode", &err);
    if (err) {
        goto out;
    }
    if (has_mode) {
        visit_type_NewImageMode(v, &mode, "mode", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_speed, "speed", &err);
    if (err) {
        goto out;
    }
    if (has_speed) {
        visit_type_int(v, &speed, "speed", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_bitmap, "bitmap", &err);
    if (err) {
        goto out;
    }
    if (has_bitmap) {
        visit_type_str(v, &bitmap, "bitmap", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_source_error, "on-source-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_source_error) {
        visit_type_BlockdevOnError(v, &on_source_error, "on-source-error", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_target_error, "on-target-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_target_error) {
        visit_type_BlockdevOnError(v, &on_target_error, "on-target-error", &err);
        if (err) {
            goto out;
        }
    }

    qmp_drive_backup(device, target, has_format, format, sync, has_mode, mode, has_speed, speed, has_bitmap, bitmap, has_on_source_error, on_source_error, has_on_target_error, on_target_error, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &target, "target", NULL);
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_str(v, &format, "format", NULL);
    }
    visit_type_MirrorSyncMode(v, &sync, "sync", NULL);
    visit_optional(v, &has_mode, "mode", NULL);
    if (has_mode) {
        visit_type_NewImageMode(v, &mode, "mode", NULL);
    }
    visit_optional(v, &has_speed, "speed", NULL);
    if (has_speed) {
        visit_type_int(v, &speed, "speed", NULL);
    }
    visit_optional(v, &has_bitmap, "bitmap", NULL);
    if (has_bitmap) {
        visit_type_str(v, &bitmap, "bitmap", NULL);
    }
    visit_optional(v, &has_on_source_error, "on-source-error", NULL);
    if (has_on_source_error) {
        visit_type_BlockdevOnError(v, &on_source_error, "on-source-error", NULL);
    }
    visit_optional(v, &has_on_target_error, "on-target-error", NULL);
    if (has_on_target_error) {
        visit_type_BlockdevOnError(v, &on_target_error, "on-target-error", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_drive_mirror(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *target = NULL;
    bool has_format = false;
    char *format = NULL;
    bool has_node_name = false;
    char *node_name = NULL;
    bool has_replaces = false;
    char *replaces = NULL;
    MirrorSyncMode sync = MIRROR_SYNC_MODE_TOP;
    bool has_mode = false;
    NewImageMode mode = NEW_IMAGE_MODE_EXISTING;
    bool has_speed = false;
    int64_t speed = 0;
    bool has_granularity = false;
    uint32_t granularity = 0;
    bool has_buf_size = false;
    int64_t buf_size = 0;
    bool has_on_source_error = false;
    BlockdevOnError on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    bool has_on_target_error = false;
    BlockdevOnError on_target_error = BLOCKDEV_ON_ERROR_REPORT;
    bool has_unmap = false;
    bool unmap = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &target, "target", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_str(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_node_name, "node-name", &err);
    if (err) {
        goto out;
    }
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_replaces, "replaces", &err);
    if (err) {
        goto out;
    }
    if (has_replaces) {
        visit_type_str(v, &replaces, "replaces", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_MirrorSyncMode(v, &sync, "sync", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_mode, "mode", &err);
    if (err) {
        goto out;
    }
    if (has_mode) {
        visit_type_NewImageMode(v, &mode, "mode", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_speed, "speed", &err);
    if (err) {
        goto out;
    }
    if (has_speed) {
        visit_type_int(v, &speed, "speed", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_granularity, "granularity", &err);
    if (err) {
        goto out;
    }
    if (has_granularity) {
        visit_type_uint32(v, &granularity, "granularity", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_buf_size, "buf-size", &err);
    if (err) {
        goto out;
    }
    if (has_buf_size) {
        visit_type_int(v, &buf_size, "buf-size", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_source_error, "on-source-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_source_error) {
        visit_type_BlockdevOnError(v, &on_source_error, "on-source-error", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_on_target_error, "on-target-error", &err);
    if (err) {
        goto out;
    }
    if (has_on_target_error) {
        visit_type_BlockdevOnError(v, &on_target_error, "on-target-error", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_unmap, "unmap", &err);
    if (err) {
        goto out;
    }
    if (has_unmap) {
        visit_type_bool(v, &unmap, "unmap", &err);
        if (err) {
            goto out;
        }
    }

    qmp_drive_mirror(device, target, has_format, format, has_node_name, node_name, has_replaces, replaces, sync, has_mode, mode, has_speed, speed, has_granularity, granularity, has_buf_size, buf_size, has_on_source_error, on_source_error, has_on_target_error, on_target_error, has_unmap, unmap, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &target, "target", NULL);
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_str(v, &format, "format", NULL);
    }
    visit_optional(v, &has_node_name, "node-name", NULL);
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", NULL);
    }
    visit_optional(v, &has_replaces, "replaces", NULL);
    if (has_replaces) {
        visit_type_str(v, &replaces, "replaces", NULL);
    }
    visit_type_MirrorSyncMode(v, &sync, "sync", NULL);
    visit_optional(v, &has_mode, "mode", NULL);
    if (has_mode) {
        visit_type_NewImageMode(v, &mode, "mode", NULL);
    }
    visit_optional(v, &has_speed, "speed", NULL);
    if (has_speed) {
        visit_type_int(v, &speed, "speed", NULL);
    }
    visit_optional(v, &has_granularity, "granularity", NULL);
    if (has_granularity) {
        visit_type_uint32(v, &granularity, "granularity", NULL);
    }
    visit_optional(v, &has_buf_size, "buf-size", NULL);
    if (has_buf_size) {
        visit_type_int(v, &buf_size, "buf-size", NULL);
    }
    visit_optional(v, &has_on_source_error, "on-source-error", NULL);
    if (has_on_source_error) {
        visit_type_BlockdevOnError(v, &on_source_error, "on-source-error", NULL);
    }
    visit_optional(v, &has_on_target_error, "on-target-error", NULL);
    if (has_on_target_error) {
        visit_type_BlockdevOnError(v, &on_target_error, "on-target-error", NULL);
    }
    visit_optional(v, &has_unmap, "unmap", NULL);
    if (has_unmap) {
        visit_type_bool(v, &unmap, "unmap", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_dump_guest_memory(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool paging = false;
    char *protocol = NULL;
    bool has_begin = false;
    int64_t begin = 0;
    bool has_length = false;
    int64_t length = 0;
    bool has_format = false;
    DumpGuestMemoryFormat format = DUMP_GUEST_MEMORY_FORMAT_ELF;

    v = qmp_input_get_visitor(qiv);
    visit_type_bool(v, &paging, "paging", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &protocol, "protocol", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_begin, "begin", &err);
    if (err) {
        goto out;
    }
    if (has_begin) {
        visit_type_int(v, &begin, "begin", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_length, "length", &err);
    if (err) {
        goto out;
    }
    if (has_length) {
        visit_type_int(v, &length, "length", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_DumpGuestMemoryFormat(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }

    qmp_dump_guest_memory(paging, protocol, has_begin, begin, has_length, length, has_format, format, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_bool(v, &paging, "paging", NULL);
    visit_type_str(v, &protocol, "protocol", NULL);
    visit_optional(v, &has_begin, "begin", NULL);
    if (has_begin) {
        visit_type_int(v, &begin, "begin", NULL);
    }
    visit_optional(v, &has_length, "length", NULL);
    if (has_length) {
        visit_type_int(v, &length, "length", NULL);
    }
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_DumpGuestMemoryFormat(v, &format, "format", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_dump_skeys(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *filename = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &filename, "filename", &err);
    if (err) {
        goto out;
    }

    qmp_dump_skeys(filename, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &filename, "filename", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_eject(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_force = false;
    bool force = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_force, "force", &err);
    if (err) {
        goto out;
    }
    if (has_force) {
        visit_type_bool(v, &force, "force", &err);
        if (err) {
            goto out;
        }
    }

    qmp_eject(device, has_force, force, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_force, "force", NULL);
    if (has_force) {
        visit_type_bool(v, &force, "force", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_expire_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *protocol = NULL;
    char *time = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &protocol, "protocol", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &time, "time", &err);
    if (err) {
        goto out;
    }

    qmp_expire_password(protocol, time, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &protocol, "protocol", NULL);
    visit_type_str(v, &time, "time", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_getfd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *fdname = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &fdname, "fdname", &err);
    if (err) {
        goto out;
    }

    qmp_getfd(fdname, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &fdname, "fdname", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_str(char *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_str(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_human_monitor_command(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    char *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *command_line = NULL;
    bool has_cpu_index = false;
    int64_t cpu_index = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &command_line, "command-line", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_cpu_index, "cpu-index", &err);
    if (err) {
        goto out;
    }
    if (has_cpu_index) {
        visit_type_int(v, &cpu_index, "cpu-index", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_human_monitor_command(command_line, has_cpu_index, cpu_index, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_str(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &command_line, "command-line", NULL);
    visit_optional(v, &has_cpu_index, "cpu-index", NULL);
    if (has_cpu_index) {
        visit_type_int(v, &cpu_index, "cpu-index", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_inject_nmi(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_inject_nmi(&err);
    error_propagate(errp, err);
}

void qmp_marshal_memsave(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t val = 0;
    int64_t size = 0;
    char *filename = NULL;
    bool has_cpu_index = false;
    int64_t cpu_index = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &val, "val", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &size, "size", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &filename, "filename", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_cpu_index, "cpu-index", &err);
    if (err) {
        goto out;
    }
    if (has_cpu_index) {
        visit_type_int(v, &cpu_index, "cpu-index", &err);
        if (err) {
            goto out;
        }
    }

    qmp_memsave(val, size, filename, has_cpu_index, cpu_index, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &val, "val", NULL);
    visit_type_int(v, &size, "size", NULL);
    visit_type_str(v, &filename, "filename", NULL);
    visit_optional(v, &has_cpu_index, "cpu-index", NULL);
    if (has_cpu_index) {
        visit_type_int(v, &cpu_index, "cpu-index", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *uri = NULL;
    bool has_blk = false;
    bool blk = false;
    bool has_inc = false;
    bool inc = false;
    bool has_detach = false;
    bool detach = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &uri, "uri", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_blk, "blk", &err);
    if (err) {
        goto out;
    }
    if (has_blk) {
        visit_type_bool(v, &blk, "blk", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_inc, "inc", &err);
    if (err) {
        goto out;
    }
    if (has_inc) {
        visit_type_bool(v, &inc, "inc", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_detach, "detach", &err);
    if (err) {
        goto out;
    }
    if (has_detach) {
        visit_type_bool(v, &detach, "detach", &err);
        if (err) {
            goto out;
        }
    }

    qmp_migrate(uri, has_blk, blk, has_inc, inc, has_detach, detach, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &uri, "uri", NULL);
    visit_optional(v, &has_blk, "blk", NULL);
    if (has_blk) {
        visit_type_bool(v, &blk, "blk", NULL);
    }
    visit_optional(v, &has_inc, "inc", NULL);
    if (has_inc) {
        visit_type_bool(v, &inc, "inc", NULL);
    }
    visit_optional(v, &has_detach, "detach", NULL);
    if (has_detach) {
        visit_type_bool(v, &detach, "detach", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate_incoming(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *uri = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &uri, "uri", &err);
    if (err) {
        goto out;
    }

    qmp_migrate_incoming(uri, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &uri, "uri", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate_set_cache_size(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t value = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &value, "value", &err);
    if (err) {
        goto out;
    }

    qmp_migrate_set_cache_size(value, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &value, "value", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate_set_capabilities(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    MigrationCapabilityStatusList *capabilities = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_MigrationCapabilityStatusList(v, &capabilities, "capabilities", &err);
    if (err) {
        goto out;
    }

    qmp_migrate_set_capabilities(capabilities, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MigrationCapabilityStatusList(v, &capabilities, "capabilities", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate_set_parameters(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_compress_level = false;
    int64_t compress_level = 0;
    bool has_compress_threads = false;
    int64_t compress_threads = 0;
    bool has_decompress_threads = false;
    int64_t decompress_threads = 0;
    bool has_x_cpu_throttle_initial = false;
    int64_t x_cpu_throttle_initial = 0;
    bool has_x_cpu_throttle_increment = false;
    int64_t x_cpu_throttle_increment = 0;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_compress_level, "compress-level", &err);
    if (err) {
        goto out;
    }
    if (has_compress_level) {
        visit_type_int(v, &compress_level, "compress-level", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_compress_threads, "compress-threads", &err);
    if (err) {
        goto out;
    }
    if (has_compress_threads) {
        visit_type_int(v, &compress_threads, "compress-threads", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_decompress_threads, "decompress-threads", &err);
    if (err) {
        goto out;
    }
    if (has_decompress_threads) {
        visit_type_int(v, &decompress_threads, "decompress-threads", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_x_cpu_throttle_initial, "x-cpu-throttle-initial", &err);
    if (err) {
        goto out;
    }
    if (has_x_cpu_throttle_initial) {
        visit_type_int(v, &x_cpu_throttle_initial, "x-cpu-throttle-initial", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_x_cpu_throttle_increment, "x-cpu-throttle-increment", &err);
    if (err) {
        goto out;
    }
    if (has_x_cpu_throttle_increment) {
        visit_type_int(v, &x_cpu_throttle_increment, "x-cpu-throttle-increment", &err);
        if (err) {
            goto out;
        }
    }

    qmp_migrate_set_parameters(has_compress_level, compress_level, has_compress_threads, compress_threads, has_decompress_threads, decompress_threads, has_x_cpu_throttle_initial, x_cpu_throttle_initial, has_x_cpu_throttle_increment, x_cpu_throttle_increment, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_compress_level, "compress-level", NULL);
    if (has_compress_level) {
        visit_type_int(v, &compress_level, "compress-level", NULL);
    }
    visit_optional(v, &has_compress_threads, "compress-threads", NULL);
    if (has_compress_threads) {
        visit_type_int(v, &compress_threads, "compress-threads", NULL);
    }
    visit_optional(v, &has_decompress_threads, "decompress-threads", NULL);
    if (has_decompress_threads) {
        visit_type_int(v, &decompress_threads, "decompress-threads", NULL);
    }
    visit_optional(v, &has_x_cpu_throttle_initial, "x-cpu-throttle-initial", NULL);
    if (has_x_cpu_throttle_initial) {
        visit_type_int(v, &x_cpu_throttle_initial, "x-cpu-throttle-initial", NULL);
    }
    visit_optional(v, &has_x_cpu_throttle_increment, "x-cpu-throttle-increment", NULL);
    if (has_x_cpu_throttle_increment) {
        visit_type_int(v, &x_cpu_throttle_increment, "x-cpu-throttle-increment", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate_start_postcopy(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_migrate_start_postcopy(&err);
    error_propagate(errp, err);
}

void qmp_marshal_migrate_cancel(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_migrate_cancel(&err);
    error_propagate(errp, err);
}

void qmp_marshal_migrate_set_downtime(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    double value = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_number(v, &value, "value", &err);
    if (err) {
        goto out;
    }

    qmp_migrate_set_downtime(value, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_number(v, &value, "value", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_migrate_set_speed(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t value = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &value, "value", &err);
    if (err) {
        goto out;
    }

    qmp_migrate_set_speed(value, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &value, "value", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_nbd_server_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    bool has_writable = false;
    bool writable = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_writable, "writable", &err);
    if (err) {
        goto out;
    }
    if (has_writable) {
        visit_type_bool(v, &writable, "writable", &err);
        if (err) {
            goto out;
        }
    }

    qmp_nbd_server_add(device, has_writable, writable, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_optional(v, &has_writable, "writable", NULL);
    if (has_writable) {
        visit_type_bool(v, &writable, "writable", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_nbd_server_start(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    SocketAddress *addr = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_SocketAddress(v, &addr, "addr", &err);
    if (err) {
        goto out;
    }

    qmp_nbd_server_start(addr, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_SocketAddress(v, &addr, "addr", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_nbd_server_stop(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_nbd_server_stop(&err);
    error_propagate(errp, err);
}

void qmp_marshal_netdev_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *id = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    qmp_netdev_del(id, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_object_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *qom_type = NULL;
    char *id = NULL;
    bool has_props = false;
    QObject *props = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &qom_type, "qom-type", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &id, "id", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_props, "props", &err);
    if (err) {
        goto out;
    }
    if (has_props) {
        visit_type_any(v, &props, "props", &err);
        if (err) {
            goto out;
        }
    }

    qmp_object_add(qom_type, id, has_props, props, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &qom_type, "qom-type", NULL);
    visit_type_str(v, &id, "id", NULL);
    visit_optional(v, &has_props, "props", NULL);
    if (has_props) {
        visit_type_any(v, &props, "props", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_object_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *id = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &id, "id", &err);
    if (err) {
        goto out;
    }

    qmp_object_del(id, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &id, "id", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_pmemsave(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t val = 0;
    int64_t size = 0;
    char *filename = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &val, "val", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &size, "size", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &filename, "filename", &err);
    if (err) {
        goto out;
    }

    qmp_pmemsave(val, size, filename, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &val, "val", NULL);
    visit_type_int(v, &size, "size", NULL);
    visit_type_str(v, &filename, "filename", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_any(QObject *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_any(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_any(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_qom_get(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QObject *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *path = NULL;
    char *property = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &path, "path", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &property, "property", &err);
    if (err) {
        goto out;
    }

    retval = qmp_qom_get(path, property, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_any(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &path, "path", NULL);
    visit_type_str(v, &property, "property", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_ObjectPropertyInfoList(ObjectPropertyInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_ObjectPropertyInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_ObjectPropertyInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_qom_list(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ObjectPropertyInfoList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *path = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &path, "path", &err);
    if (err) {
        goto out;
    }

    retval = qmp_qom_list(path, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ObjectPropertyInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &path, "path", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_ObjectTypeInfoList(ObjectTypeInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_ObjectTypeInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_ObjectTypeInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_qom_list_types(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ObjectTypeInfoList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_implements = false;
    char *implements = NULL;
    bool has_abstract = false;
    bool abstract = false;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_implements, "implements", &err);
    if (err) {
        goto out;
    }
    if (has_implements) {
        visit_type_str(v, &implements, "implements", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_abstract, "abstract", &err);
    if (err) {
        goto out;
    }
    if (has_abstract) {
        visit_type_bool(v, &abstract, "abstract", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_qom_list_types(has_implements, implements, has_abstract, abstract, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ObjectTypeInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_implements, "implements", NULL);
    if (has_implements) {
        visit_type_str(v, &implements, "implements", NULL);
    }
    visit_optional(v, &has_abstract, "abstract", NULL);
    if (has_abstract) {
        visit_type_bool(v, &abstract, "abstract", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_qom_set(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *path = NULL;
    char *property = NULL;
    QObject *value = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &path, "path", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &property, "property", &err);
    if (err) {
        goto out;
    }
    visit_type_any(v, &value, "value", &err);
    if (err) {
        goto out;
    }

    qmp_qom_set(path, property, value, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &path, "path", NULL);
    visit_type_str(v, &property, "property", NULL);
    visit_type_any(v, &value, "value", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_ACPIOSTInfoList(ACPIOSTInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_ACPIOSTInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_ACPIOSTInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_acpi_ospm_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ACPIOSTInfoList *retval;

    (void)args;

    retval = qmp_query_acpi_ospm_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ACPIOSTInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_BalloonInfo(BalloonInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_BalloonInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_BalloonInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_balloon(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BalloonInfo *retval;

    (void)args;

    retval = qmp_query_balloon(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BalloonInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_BlockInfoList(BlockInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_BlockInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_BlockInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_block(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockInfoList *retval;

    (void)args;

    retval = qmp_query_block(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_BlockJobInfoList(BlockJobInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_BlockJobInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_BlockJobInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_block_jobs(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockJobInfoList *retval;

    (void)args;

    retval = qmp_query_block_jobs(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockJobInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_BlockStatsList(BlockStatsList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_BlockStatsList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_BlockStatsList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_blockstats(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockStatsList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_query_nodes = false;
    bool query_nodes = false;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_query_nodes, "query-nodes", &err);
    if (err) {
        goto out;
    }
    if (has_query_nodes) {
        visit_type_bool(v, &query_nodes, "query-nodes", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_blockstats(has_query_nodes, query_nodes, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockStatsList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_query_nodes, "query-nodes", NULL);
    if (has_query_nodes) {
        visit_type_bool(v, &query_nodes, "query-nodes", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_ChardevInfoList(ChardevInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_ChardevInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_ChardevInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_chardev(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ChardevInfoList *retval;

    (void)args;

    retval = qmp_query_chardev(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ChardevInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_ChardevBackendInfoList(ChardevBackendInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_ChardevBackendInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_ChardevBackendInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_chardev_backends(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    ChardevBackendInfoList *retval;

    (void)args;

    retval = qmp_query_chardev_backends(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_ChardevBackendInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_CommandLineOptionInfoList(CommandLineOptionInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_CommandLineOptionInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_CommandLineOptionInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_command_line_options(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CommandLineOptionInfoList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_option = false;
    char *option = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_option, "option", &err);
    if (err) {
        goto out;
    }
    if (has_option) {
        visit_type_str(v, &option, "option", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_command_line_options(has_option, option, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CommandLineOptionInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_option, "option", NULL);
    if (has_option) {
        visit_type_str(v, &option, "option", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_CommandInfoList(CommandInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_CommandInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_CommandInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_commands(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CommandInfoList *retval;

    (void)args;

    retval = qmp_query_commands(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CommandInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_CpuDefinitionInfoList(CpuDefinitionInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_CpuDefinitionInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_CpuDefinitionInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_cpu_definitions(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuDefinitionInfoList *retval;

    (void)args;

    retval = qmp_query_cpu_definitions(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuDefinitionInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_CpuInfoList(CpuInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_CpuInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_CpuInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_cpus(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    CpuInfoList *retval;

    (void)args;

    retval = qmp_query_cpus(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_CpuInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_DumpGuestMemoryCapability(DumpGuestMemoryCapability *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_DumpGuestMemoryCapability(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_DumpGuestMemoryCapability(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_dump_guest_memory_capability(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    DumpGuestMemoryCapability *retval;

    (void)args;

    retval = qmp_query_dump_guest_memory_capability(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_DumpGuestMemoryCapability(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_EventInfoList(EventInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_EventInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_EventInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_events(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    EventInfoList *retval;

    (void)args;

    retval = qmp_query_events(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_EventInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_FdsetInfoList(FdsetInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_FdsetInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_FdsetInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_fdsets(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    FdsetInfoList *retval;

    (void)args;

    retval = qmp_query_fdsets(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_FdsetInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_IOThreadInfoList(IOThreadInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_IOThreadInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_IOThreadInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_iothreads(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    IOThreadInfoList *retval;

    (void)args;

    retval = qmp_query_iothreads(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_IOThreadInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_KvmInfo(KvmInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_KvmInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_KvmInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_kvm(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    KvmInfo *retval;

    (void)args;

    retval = qmp_query_kvm(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_KvmInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MachineInfoList(MachineInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MachineInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MachineInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_machines(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MachineInfoList *retval;

    (void)args;

    retval = qmp_query_machines(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MachineInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MemdevList(MemdevList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MemdevList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MemdevList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_memdev(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MemdevList *retval;

    (void)args;

    retval = qmp_query_memdev(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MemdevList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MemoryDeviceInfoList(MemoryDeviceInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MemoryDeviceInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MemoryDeviceInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_memory_devices(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MemoryDeviceInfoList *retval;

    (void)args;

    retval = qmp_query_memory_devices(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MemoryDeviceInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MouseInfoList(MouseInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MouseInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MouseInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_mice(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MouseInfoList *retval;

    (void)args;

    retval = qmp_query_mice(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MouseInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MigrationInfo(MigrationInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MigrationInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MigrationInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_migrate(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MigrationInfo *retval;

    (void)args;

    retval = qmp_query_migrate(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MigrationInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
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

void qmp_marshal_query_migrate_cache_size(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    int64_t retval;

    (void)args;

    retval = qmp_query_migrate_cache_size(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_int(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MigrationCapabilityStatusList(MigrationCapabilityStatusList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MigrationCapabilityStatusList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MigrationCapabilityStatusList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_migrate_capabilities(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MigrationCapabilityStatusList *retval;

    (void)args;

    retval = qmp_query_migrate_capabilities(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MigrationCapabilityStatusList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_MigrationParameters(MigrationParameters *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_MigrationParameters(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_MigrationParameters(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_migrate_parameters(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    MigrationParameters *retval;

    (void)args;

    retval = qmp_query_migrate_parameters(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_MigrationParameters(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_NameInfo(NameInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_NameInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_NameInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_name(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    NameInfo *retval;

    (void)args;

    retval = qmp_query_name(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_NameInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_BlockDeviceInfoList(BlockDeviceInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_BlockDeviceInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_BlockDeviceInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_named_block_nodes(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    BlockDeviceInfoList *retval;

    (void)args;

    retval = qmp_query_named_block_nodes(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_BlockDeviceInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_PciInfoList(PciInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_PciInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_PciInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_pci(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    PciInfoList *retval;

    (void)args;

    retval = qmp_query_pci(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_PciInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_RockerSwitch(RockerSwitch *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_RockerSwitch(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_RockerSwitch(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_rocker(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerSwitch *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }

    retval = qmp_query_rocker(name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerSwitch(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_RockerOfDpaFlowList(RockerOfDpaFlowList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_RockerOfDpaFlowList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_RockerOfDpaFlowList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_rocker_of_dpa_flows(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerOfDpaFlowList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;
    bool has_tbl_id = false;
    uint32_t tbl_id = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_tbl_id, "tbl-id", &err);
    if (err) {
        goto out;
    }
    if (has_tbl_id) {
        visit_type_uint32(v, &tbl_id, "tbl-id", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_rocker_of_dpa_flows(name, has_tbl_id, tbl_id, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerOfDpaFlowList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    visit_optional(v, &has_tbl_id, "tbl-id", NULL);
    if (has_tbl_id) {
        visit_type_uint32(v, &tbl_id, "tbl-id", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_RockerOfDpaGroupList(RockerOfDpaGroupList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_RockerOfDpaGroupList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_RockerOfDpaGroupList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_rocker_of_dpa_groups(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerOfDpaGroupList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;
    bool has_type = false;
    uint8_t type = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_type, "type", &err);
    if (err) {
        goto out;
    }
    if (has_type) {
        visit_type_uint8(v, &type, "type", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_rocker_of_dpa_groups(name, has_type, type, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerOfDpaGroupList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    visit_optional(v, &has_type, "type", NULL);
    if (has_type) {
        visit_type_uint8(v, &type, "type", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_RockerPortList(RockerPortList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_RockerPortList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_RockerPortList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_rocker_ports(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RockerPortList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }

    retval = qmp_query_rocker_ports(name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RockerPortList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_RxFilterInfoList(RxFilterInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_RxFilterInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_RxFilterInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_rx_filter(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    RxFilterInfoList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_name = false;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_name, "name", &err);
    if (err) {
        goto out;
    }
    if (has_name) {
        visit_type_str(v, &name, "name", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_query_rx_filter(has_name, name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_RxFilterInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_name, "name", NULL);
    if (has_name) {
        visit_type_str(v, &name, "name", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

static void qmp_marshal_output_SpiceInfo(SpiceInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_SpiceInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_SpiceInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_spice(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    SpiceInfo *retval;

    (void)args;

    retval = qmp_query_spice(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_SpiceInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_StatusInfo(StatusInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_StatusInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_StatusInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_status(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    StatusInfo *retval;

    (void)args;

    retval = qmp_query_status(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_StatusInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_TargetInfo(TargetInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_TargetInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_TargetInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_target(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TargetInfo *retval;

    (void)args;

    retval = qmp_query_target(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TargetInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_TPMInfoList(TPMInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_TPMInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_TPMInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_tpm(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TPMInfoList *retval;

    (void)args;

    retval = qmp_query_tpm(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TPMInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_TpmModelList(TpmModelList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_TpmModelList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_TpmModelList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_tpm_models(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TpmModelList *retval;

    (void)args;

    retval = qmp_query_tpm_models(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TpmModelList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_TpmTypeList(TpmTypeList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_TpmTypeList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_TpmTypeList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_tpm_types(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TpmTypeList *retval;

    (void)args;

    retval = qmp_query_tpm_types(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TpmTypeList(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_UuidInfo(UuidInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_UuidInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_UuidInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_uuid(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    UuidInfo *retval;

    (void)args;

    retval = qmp_query_uuid(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_UuidInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_VersionInfo(VersionInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_VersionInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_VersionInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_version(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    VersionInfo *retval;

    (void)args;

    retval = qmp_query_version(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_VersionInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_VncInfo(VncInfo *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_VncInfo(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_VncInfo(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_vnc(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    VncInfo *retval;

    (void)args;

    retval = qmp_query_vnc(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_VncInfo(retval, ret, &err);

out:
    error_propagate(errp, err);
}

static void qmp_marshal_output_VncInfo2List(VncInfo2List *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_VncInfo2List(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_VncInfo2List(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_query_vnc_servers(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    VncInfo2List *retval;

    (void)args;

    retval = qmp_query_vnc_servers(&err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_VncInfo2List(retval, ret, &err);

out:
    error_propagate(errp, err);
}

void qmp_marshal_quit(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_quit(&err);
    error_propagate(errp, err);
}

void qmp_marshal_remove_fd(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    int64_t fdset_id = 0;
    bool has_fd = false;
    int64_t fd = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_int(v, &fdset_id, "fdset-id", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_fd, "fd", &err);
    if (err) {
        goto out;
    }
    if (has_fd) {
        visit_type_int(v, &fd, "fd", &err);
        if (err) {
            goto out;
        }
    }

    qmp_remove_fd(fdset_id, has_fd, fd, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_int(v, &fdset_id, "fdset-id", NULL);
    visit_optional(v, &has_fd, "fd", NULL);
    if (has_fd) {
        visit_type_int(v, &fd, "fd", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_ringbuf_read(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    char *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    int64_t size = 0;
    bool has_format = false;
    DataFormat format = DATA_FORMAT_UTF8;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &size, "size", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_DataFormat(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }

    retval = qmp_ringbuf_read(device, size, has_format, format, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_str(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_int(v, &size, "size", NULL);
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_DataFormat(v, &format, "format", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_ringbuf_write(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *data = NULL;
    bool has_format = false;
    DataFormat format = DATA_FORMAT_UTF8;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &data, "data", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_format, "format", &err);
    if (err) {
        goto out;
    }
    if (has_format) {
        visit_type_DataFormat(v, &format, "format", &err);
        if (err) {
            goto out;
        }
    }

    qmp_ringbuf_write(device, data, has_format, format, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &data, "data", NULL);
    visit_optional(v, &has_format, "format", NULL);
    if (has_format) {
        visit_type_DataFormat(v, &format, "format", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_rtc_reset_reinjection(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_rtc_reset_reinjection(&err);
    error_propagate(errp, err);
}

void qmp_marshal_screendump(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *filename = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &filename, "filename", &err);
    if (err) {
        goto out;
    }

    qmp_screendump(filename, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &filename, "filename", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_send_key(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    KeyValueList *keys = NULL;
    bool has_hold_time = false;
    int64_t hold_time = 0;

    v = qmp_input_get_visitor(qiv);
    visit_type_KeyValueList(v, &keys, "keys", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_hold_time, "hold-time", &err);
    if (err) {
        goto out;
    }
    if (has_hold_time) {
        visit_type_int(v, &hold_time, "hold-time", &err);
        if (err) {
            goto out;
        }
    }

    qmp_send_key(keys, has_hold_time, hold_time, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_KeyValueList(v, &keys, "keys", NULL);
    visit_optional(v, &has_hold_time, "hold-time", NULL);
    if (has_hold_time) {
        visit_type_int(v, &hold_time, "hold-time", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_set_link(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;
    bool up = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &up, "up", &err);
    if (err) {
        goto out;
    }

    qmp_set_link(name, up, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    visit_type_bool(v, &up, "up", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_set_password(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *protocol = NULL;
    char *password = NULL;
    bool has_connected = false;
    char *connected = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &protocol, "protocol", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &password, "password", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_connected, "connected", &err);
    if (err) {
        goto out;
    }
    if (has_connected) {
        visit_type_str(v, &connected, "connected", &err);
        if (err) {
            goto out;
        }
    }

    qmp_set_password(protocol, password, has_connected, connected, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &protocol, "protocol", NULL);
    visit_type_str(v, &password, "password", NULL);
    visit_optional(v, &has_connected, "connected", NULL);
    if (has_connected) {
        visit_type_str(v, &connected, "connected", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_stop(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_stop(&err);
    error_propagate(errp, err);
}

void qmp_marshal_system_powerdown(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_system_powerdown(&err);
    error_propagate(errp, err);
}

void qmp_marshal_system_reset(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_system_reset(&err);
    error_propagate(errp, err);
}

void qmp_marshal_system_wakeup(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;

    (void)args;

    qmp_system_wakeup(&err);
    error_propagate(errp, err);
}

static void qmp_marshal_output_TraceEventInfoList(TraceEventInfoList *ret_in, QObject **ret_out, Error **errp)
{
    Error *err = NULL;
    QmpOutputVisitor *qov = qmp_output_visitor_new();
    QapiDeallocVisitor *qdv;
    Visitor *v;

    v = qmp_output_get_visitor(qov);
    visit_type_TraceEventInfoList(v, &ret_in, "unused", &err);
    if (err) {
        goto out;
    }
    *ret_out = qmp_output_get_qobject(qov);

out:
    error_propagate(errp, err);
    qmp_output_visitor_cleanup(qov);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_TraceEventInfoList(v, &ret_in, "unused", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_trace_event_get_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    TraceEventInfoList *retval;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }

    retval = qmp_trace_event_get_state(name, &err);
    if (err) {
        goto out;
    }

    qmp_marshal_output_TraceEventInfoList(retval, ret, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_trace_event_set_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *name = NULL;
    bool enable = false;
    bool has_ignore_unavailable = false;
    bool ignore_unavailable = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &name, "name", &err);
    if (err) {
        goto out;
    }
    visit_type_bool(v, &enable, "enable", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_ignore_unavailable, "ignore-unavailable", &err);
    if (err) {
        goto out;
    }
    if (has_ignore_unavailable) {
        visit_type_bool(v, &ignore_unavailable, "ignore-unavailable", &err);
        if (err) {
            goto out;
        }
    }

    qmp_trace_event_set_state(name, enable, has_ignore_unavailable, ignore_unavailable, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &name, "name", NULL);
    visit_type_bool(v, &enable, "enable", NULL);
    visit_optional(v, &has_ignore_unavailable, "ignore-unavailable", NULL);
    if (has_ignore_unavailable) {
        visit_type_bool(v, &ignore_unavailable, "ignore-unavailable", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_transaction(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    TransactionActionList *actions = NULL;
    bool has_properties = false;
    TransactionProperties *properties = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_TransactionActionList(v, &actions, "actions", &err);
    if (err) {
        goto out;
    }
    visit_optional(v, &has_properties, "properties", &err);
    if (err) {
        goto out;
    }
    if (has_properties) {
        visit_type_TransactionProperties(v, &properties, "properties", &err);
        if (err) {
            goto out;
        }
    }

    qmp_transaction(actions, has_properties, properties, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_TransactionActionList(v, &actions, "actions", NULL);
    visit_optional(v, &has_properties, "properties", NULL);
    if (has_properties) {
        visit_type_TransactionProperties(v, &properties, "properties", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_x_blockdev_del(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_id = false;
    char *id = NULL;
    bool has_node_name = false;
    char *node_name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_id, "id", &err);
    if (err) {
        goto out;
    }
    if (has_id) {
        visit_type_str(v, &id, "id", &err);
        if (err) {
            goto out;
        }
    }
    visit_optional(v, &has_node_name, "node-name", &err);
    if (err) {
        goto out;
    }
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", &err);
        if (err) {
            goto out;
        }
    }

    qmp_x_blockdev_del(has_id, id, has_node_name, node_name, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_id, "id", NULL);
    if (has_id) {
        visit_type_str(v, &id, "id", NULL);
    }
    visit_optional(v, &has_node_name, "node-name", NULL);
    if (has_node_name) {
        visit_type_str(v, &node_name, "node-name", NULL);
    }
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_x_blockdev_insert_medium(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;
    char *node_name = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }
    visit_type_str(v, &node_name, "node-name", &err);
    if (err) {
        goto out;
    }

    qmp_x_blockdev_insert_medium(device, node_name, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    visit_type_str(v, &node_name, "node-name", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_x_blockdev_remove_medium(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *device = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &device, "device", &err);
    if (err) {
        goto out;
    }

    qmp_x_blockdev_remove_medium(device, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &device, "device", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_x_input_send_event(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool has_console = false;
    int64_t console = 0;
    InputEventList *events = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_optional(v, &has_console, "console", &err);
    if (err) {
        goto out;
    }
    if (has_console) {
        visit_type_int(v, &console, "console", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_InputEventList(v, &events, "events", &err);
    if (err) {
        goto out;
    }

    qmp_x_input_send_event(has_console, console, events, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_optional(v, &has_console, "console", NULL);
    if (has_console) {
        visit_type_int(v, &console, "console", NULL);
    }
    visit_type_InputEventList(v, &events, "events", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_xen_save_devices_state(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    char *filename = NULL;

    v = qmp_input_get_visitor(qiv);
    visit_type_str(v, &filename, "filename", &err);
    if (err) {
        goto out;
    }

    qmp_xen_save_devices_state(filename, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_str(v, &filename, "filename", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}

void qmp_marshal_xen_set_global_dirty_log(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    bool enable = false;

    v = qmp_input_get_visitor(qiv);
    visit_type_bool(v, &enable, "enable", &err);
    if (err) {
        goto out;
    }

    qmp_xen_set_global_dirty_log(enable, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_bool(v, &enable, "enable", NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}
