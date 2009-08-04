#include <dbus/dbus.h>
#include <stdio.h>
#include <assert.h>

#include "dbus.h"
#include "iopause.h"

int dbus_fd[kMaxWatches];
char dbus_fd_read[kMaxWatches];
char dbus_fd_write[kMaxWatches];

static DBusWatch* dbus_watches[kMaxWatches];

static void watches_setup() {
  for (unsigned i = 0; i < kMaxWatches; ++i) {
    DBusWatch* const watch = dbus_watches[i];
    if (watch) {
      if (dbus_watch_get_enabled(watch)) {
        const int flags = dbus_watch_get_flags(watch);
        dbus_fd[i] = dbus_watch_get_unix_fd(watch);
        dbus_fd_read[i] = flags & DBUS_WATCH_READABLE;
        dbus_fd_write[i] = flags & DBUS_WATCH_WRITABLE;
      }
    } else {
      dbus_fd[i] = -1;
    }
  }
}

static dbus_bool_t watch_add(DBusWatch *watch, void *data) {
  for (unsigned i = 0; i < kMaxWatches; ++i) {
    if (!dbus_watches[i]) {
      dbus_watches[i] = watch;
      watches_setup();
      return 1;
    }
  }

  return 0;
}

static void watch_remove(DBusWatch *watch, void *data) {
  for (unsigned i = 0; i < kMaxWatches; ++i) {
    if (dbus_watches[i] == watch) {
      dbus_watches[i] = NULL;
      break;
    }
  }
}

static void watch_toggle(DBusWatch *watch, void *data) {
  watches_setup();
}

DBusHandlerResult cache_message(DBusConnection* connection, DBusMessage* message, void* user_data) {
  if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_METHOD_CALL ||
      !dbus_message_has_path(message, "/cache") ||
      !dbus_message_has_interface(message, "org.chromium.LocalDNSCache")) {
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  const char* method = dbus_message_get_member(message);
  printf("got %s\n", method);
  return DBUS_HANDLER_RESULT_HANDLED;
}

static const struct DBusObjectPathVTable cache_vtable = {
  .unregister_function = NULL,
  .message_function = cache_message,
};

static DBusConnection *conn;

void dbus_pre_iopause() {
  while (dbus_connection_get_dispatch_status(conn) == DBUS_DISPATCH_DATA_REMAINS)
    dbus_connection_dispatch(conn);
}

void dbus_handle_io(int index, int resulting_events) {
  const int result = (IOPAUSE_READ & resulting_events ? DBUS_WATCH_READABLE : 0) |
                     (IOPAUSE_WRITE & resulting_events ? DBUS_WATCH_WRITABLE : 0);
  dbus_watch_handle(dbus_watches[index], result);
}

int
dbus_init() {
  DBusError error;

  dbus_error_init(&error);
  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  if (!conn) {
      fprintf (stderr, "%s: %s\n", error.name, error.message);
      return 0;
  }

  dbus_bus_request_name (conn, "org.chromium.local-dns-cache", 0, &error);
  if (dbus_error_is_set (&error)) {
    fprintf (stderr, "%s: %s\n", error.name, error.message);
    return 0;
  }

  dbus_connection_set_watch_functions(conn, watch_add, watch_remove, watch_toggle, NULL, NULL);
  dbus_connection_register_object_path(conn, "/cache", &cache_vtable, NULL);

  return 1;
}
