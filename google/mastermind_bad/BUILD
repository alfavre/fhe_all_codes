load("//transpiler:fhe.bzl", "fhe_cc_library")
load("@bazel_skylib//:bzl_library.bzl", "bzl_library")

licenses(["notice"])

cc_library(
    name = "mastermind_bad",
    srcs = ["mastermind_bad.cc"],
    hdrs = ["mastermind_bad.h"],
)

fhe_cc_library(
    name = "mastermind_bad_tfhe",
    src = "mastermind_bad.cc",
    hdrs = ["mastermind_bad.h"],
    num_opt_passes = 2,
)


cc_binary(
    name = "mastermind_bad_tfhe_testbench",
    srcs = ["mastermind_bad_tfhe_testbench.cc"],
    deps = [
        ":mastermind_bad_tfhe",
        "//transpiler/data:fhe_data",
        "@com_google_xls//xls/common/logging",
        "@com_google_xls//xls/common/status:status_macros",
        "@tfhe//:libtfhe",
    ],
)
