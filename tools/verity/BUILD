load("//tools:defs.bzl", "go_binary")

licenses(["notice"])

go_binary(
    name = "measure_tool",
    srcs = [
        "measure_tool.go",
    ],
    nocgo = 1,
    deps = [
        "//pkg/abi/linux",
    ],
)
