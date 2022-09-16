load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "direct",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dentryListElem",
        "Linker": "*dentryListElem",
    },
)

go_template_instance(
    name = "special_fd_list",
    out = "special_fd_list.go",
    package = "direct",
    prefix = "specialFD",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*specialFileFD",
        "Linker": "*specialFileFD",
    },
)

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "direct",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "dentry",
    },
)

go_library(
    name = "direct",
    srcs = [
        "dentry_list.go",
        "direct.go",
        "direct_amd64_unsafe.go",
        "direct_arm64_unsafe.go",
        "direct_unsafe.go",
        "directory.go",
        "filesystem.go",
        "fstree.go",
        "handle.go",
        "host_named_pipe.go",
        "regular_file.go",
        "socket.go",
        "special_fd_list.go",
        "special_file.go",
        "symlink.go",
        "time.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/metric",
        "//pkg/p9",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsimpl/host",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/unet",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "direct_test",
    srcs = ["direct_test.go"],
    library = ":direct",
    deps = [
        "//pkg/sentry/contexttest",
        "//pkg/sentry/kernel/time",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
