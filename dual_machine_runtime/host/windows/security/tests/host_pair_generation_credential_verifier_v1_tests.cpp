#include "vfdual/host_pair_generation_credential_verifier_v1.hpp"
#include "vfdual/host_pair_generation_credential_keyring_build.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

static_assert(!std::is_default_constructible_v<
    vfdual::VerifiedHostPairGenerationCredentialV1>);
static_assert(std::is_nothrow_copy_constructible_v<
    vfdual::VerifiedHostPairGenerationCredentialV1>);

namespace {

// Cross-language RS256 fixtures use 3072-bit RSA keys. Their private halves
// were discarded after signing these canonical server-contract tokens.
constexpr std::array<std::uint8_t, 422U> kCurrentPublicSpkiDer{
    0x30U, 0x82U, 0x01U, 0xa2U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x2aU, 0x86U, 0x48U, 0x86U,
    0xf7U, 0x0dU, 0x01U, 0x01U, 0x01U, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x8fU, 0x00U,
    0x30U, 0x82U, 0x01U, 0x8aU, 0x02U, 0x82U, 0x01U, 0x81U, 0x00U, 0xa8U, 0xf6U, 0x9dU,
    0xa1U, 0x59U, 0xd6U, 0x30U, 0x4bU, 0x93U, 0x28U, 0xc0U, 0x53U, 0xd8U, 0x6dU, 0xbfU,
    0x9aU, 0x16U, 0x03U, 0xa2U, 0x60U, 0x1dU, 0xbcU, 0xe9U, 0x4fU, 0xe7U, 0xe2U, 0x8dU,
    0x4eU, 0x2fU, 0x93U, 0xf4U, 0xa5U, 0x63U, 0x6eU, 0x9aU, 0x60U, 0x39U, 0x6fU, 0x0cU,
    0x02U, 0x7eU, 0x78U, 0x1aU, 0xe3U, 0x96U, 0x69U, 0x26U, 0xcdU, 0x83U, 0x86U, 0xe4U,
    0x8eU, 0x1fU, 0x45U, 0x5cU, 0xc1U, 0x81U, 0x14U, 0xa6U, 0xbbU, 0x07U, 0x62U, 0x6bU,
    0x37U, 0x1bU, 0x1aU, 0x5eU, 0xa5U, 0x63U, 0xd7U, 0x46U, 0x10U, 0x2bU, 0x24U, 0x5bU,
    0x20U, 0x3aU, 0x52U, 0x8bU, 0x12U, 0x11U, 0x44U, 0x1dU, 0x60U, 0xf5U, 0x77U, 0x4eU,
    0x3eU, 0xa0U, 0x4fU, 0x22U, 0x50U, 0x4cU, 0x33U, 0xa5U, 0x64U, 0x44U, 0x23U, 0xebU,
    0x3cU, 0x1fU, 0x6dU, 0x6cU, 0x0bU, 0x5fU, 0x7eU, 0x63U, 0x96U, 0x1bU, 0x69U, 0x41U,
    0x59U, 0x17U, 0x41U, 0xdaU, 0xfaU, 0x71U, 0x4cU, 0xfcU, 0x1eU, 0x30U, 0x94U, 0x63U,
    0xdaU, 0x53U, 0xc9U, 0x3aU, 0x0cU, 0xd1U, 0x5bU, 0x4eU, 0xbfU, 0x18U, 0x3fU, 0xc7U,
    0x31U, 0xdfU, 0xb3U, 0x7eU, 0xa7U, 0x05U, 0x1bU, 0x46U, 0x07U, 0xbcU, 0xfdU, 0x7cU,
    0x40U, 0xcdU, 0x43U, 0x03U, 0xe8U, 0xceU, 0xd3U, 0x68U, 0x0cU, 0x40U, 0x6dU, 0x84U,
    0x29U, 0xcfU, 0x33U, 0xfeU, 0x96U, 0x22U, 0x94U, 0xe5U, 0xb7U, 0xaeU, 0xf3U, 0x0aU,
    0xedU, 0x24U, 0xdbU, 0x19U, 0x01U, 0x3fU, 0x00U, 0x8eU, 0x53U, 0x63U, 0xb4U, 0x7eU,
    0x06U, 0x69U, 0x7fU, 0x71U, 0x99U, 0x3aU, 0x97U, 0xacU, 0x15U, 0x43U, 0x39U, 0xe0U,
    0x90U, 0x62U, 0x17U, 0x87U, 0x96U, 0x36U, 0x64U, 0x5cU, 0x74U, 0x27U, 0x7fU, 0x04U,
    0x17U, 0x48U, 0x0fU, 0xebU, 0xd5U, 0x30U, 0xe6U, 0x54U, 0xdaU, 0xf6U, 0x72U, 0x44U,
    0xcdU, 0x17U, 0xa5U, 0x76U, 0xfeU, 0x44U, 0x22U, 0x7dU, 0xe1U, 0xf2U, 0x75U, 0x79U,
    0x05U, 0x28U, 0xc7U, 0xbdU, 0x40U, 0x1cU, 0x9fU, 0x55U, 0xbaU, 0x32U, 0x90U, 0x5eU,
    0xe2U, 0x78U, 0xb3U, 0x7dU, 0x2eU, 0x10U, 0x3cU, 0xaeU, 0xceU, 0x22U, 0xaeU, 0xbdU,
    0xe3U, 0x31U, 0x53U, 0x9dU, 0x29U, 0x29U, 0x6eU, 0x1eU, 0xafU, 0xe0U, 0x30U, 0x9fU,
    0xfeU, 0x8aU, 0x62U, 0x6bU, 0x41U, 0xc2U, 0x05U, 0xc9U, 0xedU, 0x42U, 0x5bU, 0x47U,
    0xebU, 0x92U, 0x2eU, 0x77U, 0xb4U, 0xe0U, 0x0aU, 0x52U, 0xd0U, 0x8cU, 0x73U, 0x5eU,
    0xd2U, 0xdbU, 0x13U, 0xe2U, 0x0cU, 0x9eU, 0xffU, 0x39U, 0xccU, 0x61U, 0x81U, 0xd8U,
    0xe4U, 0x8fU, 0x7bU, 0x8dU, 0xceU, 0x55U, 0x90U, 0x62U, 0xf6U, 0xb4U, 0x82U, 0xdbU,
    0x54U, 0xb1U, 0xfeU, 0x95U, 0x8fU, 0xfcU, 0x8fU, 0x72U, 0x8eU, 0x6bU, 0x5fU, 0x02U,
    0xa2U, 0xa9U, 0xb8U, 0xf4U, 0x73U, 0x4bU, 0x13U, 0xa4U, 0x3bU, 0xd5U, 0xc8U, 0x96U,
    0xdaU, 0x85U, 0x8dU, 0xd7U, 0xd3U, 0x30U, 0x55U, 0xa2U, 0x2bU, 0x2fU, 0x81U, 0x0eU,
    0x35U, 0x09U, 0xdbU, 0x0eU, 0x6aU, 0xc2U, 0xdeU, 0xc2U, 0xbcU, 0x39U, 0xa7U, 0x79U,
    0xa2U, 0xa6U, 0xfeU, 0x0cU, 0xd9U, 0x40U, 0x0eU, 0x08U, 0xefU, 0x71U, 0xb7U, 0x65U,
    0xf1U, 0x09U, 0x93U, 0x93U, 0xddU, 0x34U, 0xd0U, 0x78U, 0x9bU, 0x02U, 0x03U, 0x01U,
    0x00U, 0x01U,
};

constexpr std::array<std::uint8_t, 422U> kPreviousPublicSpkiDer{
    0x30U, 0x82U, 0x01U, 0xa2U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x2aU, 0x86U, 0x48U, 0x86U,
    0xf7U, 0x0dU, 0x01U, 0x01U, 0x01U, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x8fU, 0x00U,
    0x30U, 0x82U, 0x01U, 0x8aU, 0x02U, 0x82U, 0x01U, 0x81U, 0x00U, 0xa9U, 0x8eU, 0x5dU,
    0xe7U, 0x11U, 0xa2U, 0x46U, 0x02U, 0xe2U, 0xedU, 0x88U, 0x2eU, 0x02U, 0x4eU, 0x7dU,
    0x6fU, 0x11U, 0x3fU, 0x55U, 0x06U, 0x0bU, 0x8aU, 0x72U, 0xd0U, 0x63U, 0x74U, 0x71U,
    0x64U, 0x0aU, 0xbaU, 0xc0U, 0x4dU, 0xa4U, 0xfaU, 0x7dU, 0x63U, 0xefU, 0xfaU, 0x36U,
    0x09U, 0x7eU, 0xf2U, 0x29U, 0x6cU, 0xd5U, 0x76U, 0xc9U, 0x4fU, 0x40U, 0xe5U, 0x20U,
    0xcbU, 0xb7U, 0xffU, 0x56U, 0x19U, 0x1cU, 0x73U, 0xf2U, 0x8aU, 0x3bU, 0xf0U, 0xa6U,
    0x44U, 0x0aU, 0xffU, 0xd9U, 0x5dU, 0x89U, 0x06U, 0xdcU, 0x3bU, 0x20U, 0x7aU, 0xbdU,
    0x0cU, 0x9fU, 0x74U, 0x31U, 0x17U, 0xb0U, 0x01U, 0x40U, 0xcbU, 0xc5U, 0xffU, 0xcaU,
    0xa2U, 0x08U, 0xbaU, 0x9aU, 0xbfU, 0x70U, 0xe3U, 0x77U, 0x1cU, 0x02U, 0xbeU, 0xc7U,
    0x48U, 0x80U, 0xa6U, 0x5bU, 0xc3U, 0x0dU, 0x43U, 0x1eU, 0x2eU, 0xc9U, 0xaaU, 0xe8U,
    0xfdU, 0x5fU, 0x15U, 0xe8U, 0xd7U, 0x54U, 0x3fU, 0xa2U, 0x86U, 0x57U, 0xfbU, 0x86U,
    0xa7U, 0x93U, 0x9dU, 0xd9U, 0x7dU, 0x1eU, 0x89U, 0x9aU, 0xa3U, 0x3aU, 0xc9U, 0x2eU,
    0x1dU, 0x56U, 0xaaU, 0x84U, 0xa7U, 0x0eU, 0x31U, 0xaeU, 0x3aU, 0x1cU, 0x2bU, 0x4eU,
    0xb8U, 0x8cU, 0xd8U, 0xe4U, 0xf3U, 0xd4U, 0x1cU, 0xf2U, 0x49U, 0x2dU, 0x33U, 0xccU,
    0x56U, 0x5eU, 0x44U, 0x08U, 0x1dU, 0xcbU, 0x06U, 0x0bU, 0xf8U, 0x03U, 0xe8U, 0x38U,
    0x24U, 0x98U, 0x59U, 0xb4U, 0x41U, 0xe3U, 0xa0U, 0x70U, 0x95U, 0xadU, 0xceU, 0xfeU,
    0x11U, 0x4aU, 0xd6U, 0x3bU, 0x36U, 0x5bU, 0x57U, 0x3fU, 0x2fU, 0x3fU, 0xd1U, 0x90U,
    0x17U, 0x79U, 0xc1U, 0xf1U, 0xc6U, 0xfdU, 0x6cU, 0x0dU, 0xe7U, 0x56U, 0x41U, 0xd2U,
    0x07U, 0xc5U, 0x0bU, 0x00U, 0x43U, 0x65U, 0xd4U, 0x29U, 0xa9U, 0x19U, 0x18U, 0xf0U,
    0xf9U, 0xd0U, 0x7dU, 0x2bU, 0x37U, 0x0eU, 0x3eU, 0x52U, 0xe3U, 0xe0U, 0x4aU, 0xdfU,
    0x23U, 0x50U, 0x4eU, 0xd0U, 0xefU, 0xf7U, 0xb4U, 0x66U, 0xd1U, 0x17U, 0x0eU, 0x3fU,
    0x4fU, 0xe4U, 0xa4U, 0x0bU, 0x9aU, 0x05U, 0x06U, 0xcdU, 0xe4U, 0xb1U, 0x1cU, 0xdbU,
    0xcaU, 0x94U, 0x7aU, 0x4fU, 0xafU, 0xc7U, 0x21U, 0x1fU, 0xaaU, 0xbeU, 0x22U, 0x6eU,
    0x5bU, 0xbdU, 0xa8U, 0x84U, 0xfdU, 0x4eU, 0xffU, 0x3bU, 0xd4U, 0xa6U, 0xe0U, 0xfbU,
    0xadU, 0x0eU, 0x09U, 0xe7U, 0x59U, 0x58U, 0x11U, 0x79U, 0xb8U, 0xf5U, 0x68U, 0xcdU,
    0x75U, 0xbdU, 0x07U, 0xe3U, 0x24U, 0x12U, 0xb9U, 0x9cU, 0x25U, 0xd8U, 0x1aU, 0x83U,
    0xd1U, 0xc7U, 0x54U, 0x6cU, 0xedU, 0xbeU, 0x80U, 0x19U, 0x49U, 0x96U, 0x03U, 0xc4U,
    0x5cU, 0x4cU, 0x2aU, 0x49U, 0x67U, 0xcdU, 0x94U, 0x77U, 0x8bU, 0x24U, 0x99U, 0x5aU,
    0xc2U, 0x19U, 0xe5U, 0x53U, 0xe3U, 0xbfU, 0x0cU, 0x71U, 0x85U, 0xfbU, 0xe7U, 0x7aU,
    0x71U, 0xaaU, 0xafU, 0x0fU, 0x4dU, 0x18U, 0xfcU, 0xf4U, 0x2fU, 0xd6U, 0x2dU, 0x51U,
    0x22U, 0x3cU, 0x43U, 0x82U, 0xc9U, 0x3eU, 0xe6U, 0x71U, 0xc5U, 0x2aU, 0x09U, 0x2eU,
    0xa5U, 0x72U, 0x03U, 0x09U, 0x18U, 0x41U, 0x56U, 0x6eU, 0xc2U, 0xa3U, 0x60U, 0xfdU,
    0x90U, 0x07U, 0x1dU, 0xa6U, 0x90U, 0x63U, 0x2cU, 0xe1U, 0x3dU, 0x02U, 0x03U, 0x01U,
    0x00U, 0x01U,
};

constexpr std::string_view kCurrentKeyId{"2db63e5ddb039fd4"};
constexpr std::string_view kPreviousKeyId{"2044d2e7af7a196a"};
constexpr std::string_view kCurrentTokenSha256{
    "8b066ea25a3b1e8a4b397665f088ecbf9899ecb4d9ba1c73df19a3e7d22f8afe"};
constexpr std::string_view kCurrentToken{
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJkYjYzZTVkZGIwMzlmZDQiLCJ0eXAiOiJKV1QifQ.eyJhbGxvY2F0aW9uX3Jlc"
    "XVlc3RfaWQiOiJhbGxvY2F0aW9uLnJlcTpob3N0LTEiLCJhbmRyb2lkX2lkZW50aXR5X3Nwa2lfc2hhMjU2IjoiNTU1N"
    "TU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NSIsImF1ZCI6I"
    "nZpc2lvbmZvcmdlLWR1YWwtbWFjaGluZS1wZWVyLWhhbmRzaGFrZS12MSIsImJpbmRpbmdfaWQiOiIzMzMzMzMzMzMzM"
    "zMzMzMzMzMzMzMzMzMzMzMzMzMzMyIsImJpbmRpbmdfcmV2aXNpb24iOjMsImNvbm5lY3Rpb25faWQiOjgsImNyZWRlb"
    "nRpYWxfbm9uY2UiOiI3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N"
    "zc3Nzc3Nzc3IiwiZW50aXRsZW1lbnRfaWQiOiIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsImV4cCI6M"
    "TkwMDAwMDAxNSwiZ2VuZXJhdGlvbiI6NywiaG9zdF9pZGVudGl0eV9zcGtpX3NoYTI1NiI6IjQ0NDQ0NDQ0NDQ0NDQ0N"
    "DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQiLCJpYXQiOjE5MDAwMDAwMDAsI"
    "mlzcyI6InZpc2lvbmZvcmdlLWR1YWwtbWFjaGluZS1zZXJ2aWNlIiwibmJmIjoxOTAwMDAwMDAwLCJwYWlyX2lkIjoiM"
    "TExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJyZXZvY2F0aW9uX3ZlcnNpb24iOjQsInRyYW5zY3JpcHRfc"
    "HJvcG9zYWxfc2hhMjU2IjoiNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2N"
    "jY2NjY2NjY2NjY2NiIsInR5cCI6InZmLWR1YWwtbWFjaGluZS1wYWlyLWdlbmVyYXRpb24tY3JlZGVudGlhbC12MSJ9."
    "JGwbsG0Y_1Tte3w9uQWXlDDbu9l7OPZTenDIVzHeh4MXeNtE_XfE_rwPL1KiMhcNtDksTlRsIY9gjNfjwDId3j2WEkeD"
    "Bl7tq8ztCBTGOS2on_otO5u3EWqaljP1N6Ja4pnNRN6UYmN1lrU7QdFFa3iAzVBMaho4s9S3ERi_rQOyZh_4FlnLkYfM"
    "L_NdbUUiSmFno3m5QHBjlfvPAeQtpHVzC2Z-g-ta1gs__PuWeGn08qT7OHMOPXOe-6F2-_-"
    "LCsxtsnQ3RDFGYGsDQDBjIBbClUegsKaUMOOxzs_Eqb2B0EFuebQ-o5dsjS_o20EuN_nh4CS8g7f4ns286MNp0tX5YJJJROBmWf6YRfdJD0MxUP4ZicvReqmFdCrGzf-qqWPwJKqE-LcfuVEF"
    "yt7n69QXj4d_pb1-7dDSjEbkd-x91HvxElY0eioATnrExhoYgTZvXXGuPlA3X_eB3y99iPh8S53GnXi2dduZ-H6VL-"
    "bXC36O_eRj40OlgK4ZMFDG"};

constexpr std::string_view kPreviousToken{
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwNDRkMmU3YWY3YTE5NmEiLCJ0eXAiOiJKV1QifQ.eyJhbGxvY2F0aW9uX3Jlc"
    "XVlc3RfaWQiOiJhbGxvY2F0aW9uLnJlcTpob3N0LTEiLCJhbmRyb2lkX2lkZW50aXR5X3Nwa2lfc2hhMjU2IjoiNTU1N"
    "TU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NSIsImF1ZCI6I"
    "nZpc2lvbmZvcmdlLWR1YWwtbWFjaGluZS1wZWVyLWhhbmRzaGFrZS12MSIsImJpbmRpbmdfaWQiOiIzMzMzMzMzMzMzM"
    "zMzMzMzMzMzMzMzMzMzMzMzMzMzMyIsImJpbmRpbmdfcmV2aXNpb24iOjMsImNvbm5lY3Rpb25faWQiOjgsImNyZWRlb"
    "nRpYWxfbm9uY2UiOiI3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N"
    "zc3Nzc3Nzc3IiwiZW50aXRsZW1lbnRfaWQiOiIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsImV4cCI6M"
    "TkwMDAwMDAxNSwiZ2VuZXJhdGlvbiI6NywiaG9zdF9pZGVudGl0eV9zcGtpX3NoYTI1NiI6IjQ0NDQ0NDQ0NDQ0NDQ0N"
    "DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQiLCJpYXQiOjE5MDAwMDAwMDAsI"
    "mlzcyI6InZpc2lvbmZvcmdlLWR1YWwtbWFjaGluZS1zZXJ2aWNlIiwibmJmIjoxOTAwMDAwMDAwLCJwYWlyX2lkIjoiM"
    "TExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJyZXZvY2F0aW9uX3ZlcnNpb24iOjQsInRyYW5zY3JpcHRfc"
    "HJvcG9zYWxfc2hhMjU2IjoiNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2N"
    "jY2NjY2NjY2NjY2NiIsInR5cCI6InZmLWR1YWwtbWFjaGluZS1wYWlyLWdlbmVyYXRpb24tY3JlZGVudGlhbC12MSJ9."
    "qUpsVWB5UU23jEBzYCwC6HEQkYewhfgJcffs3lI81r_i7oosacu17i6aPrSlMhtysX6R5gtO_vdazjaTvh5yiqMJySNz"
    "f36gtEIlgGunahdJXUMJOb3ZJKOdxb23Iobxpn-UVvw0ulmVJBOF-SROVUMtzWvIW6J6fOHqFHTMtG3ME7bSZBMd8Qxu"
    "ZNgYZCfKrSDuxcupPqNekQYJCrk5uXXFbpGEoRAm_zTofVPaAv0v2tqwQy3_1hIWs35cJAN3DDkX95ewDPxzHvyMYsHC"
    "mY7p8jkzIjAl5kmpp686YDmIsfq039BoCu8rmlnuxKEBbRqYAxAsKTtUANfbxC3bbBwGSqtalgaR7J6q3jlQCNRhg37W"
    "3xosf7jWmrf8w2SRJfsCTeUUF9iLcaxhGfTCZKKmgoGdxMc12vbK2b9s-8HJz-"
    "4FG1iB5xBRTKvVAe3hrCp0v__I8hS50j2XNOrPlvTbMD3JlMCKTM5JSlL5OmHl5puAjOU6vaw1UE03B3by"};

constexpr std::int64_t kNowEpoch = 1'900'000'000;

void require(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

[[nodiscard]] std::string repeat(
    const char value, const std::size_t count) {
    return std::string(count, value);
}

[[nodiscard]] vfdual::HostPairGenerationCredentialExpectedV1 expected() {
    return {
        .allocation_request_id = "allocation.req:host-1",
        .pair_id = repeat('1', 32U),
        .entitlement_id = repeat('2', 32U),
        .binding_id = repeat('3', 32U),
        .binding_revision = 3,
        .revocation_version = 4,
        .generation = 7,
        .connection_id = 8,
        .host_identity_spki_sha256 = repeat('4', 64U),
        .android_identity_spki_sha256 = repeat('5', 64U),
        .transcript_proposal_sha256 = repeat('6', 64U),
    };
}

[[nodiscard]] std::string lower_hex(
    const std::array<std::uint8_t, 32U>& value) {
    constexpr std::string_view digits{"0123456789abcdef"};
    std::string result(value.size() * 2U, '0');
    for (std::size_t index{}; index < value.size(); ++index) {
        result[index * 2U] = digits[value[index] >> 4U];
        result[index * 2U + 1U] = digits[value[index] & 0x0fU];
    }
    return result;
}

[[nodiscard]] std::unique_ptr<
    vfdual::HostPairGenerationCredentialV1Verifier> make_verifier() {
    const std::array keys{
        vfdual::HostPairGenerationCredentialTestPublicKeyV1{
            kCurrentPublicSpkiDer},
        vfdual::HostPairGenerationCredentialTestPublicKeyV1{
            kPreviousPublicSpkiDer},
    };
    const std::array<
        vfdual::HostPairGenerationCredentialTestPublicKeyV1, 0U> other{};
    auto result = vfdual::HostPairGenerationCredentialV1Verifier::
        create_for_test_fixture_keyring(keys, other);
    VFDUAL_TEST_REQUIRE(result.succeeded());
    return std::move(result.verifier);
}

void require_error(
    const vfdual::HostPairGenerationCredentialVerificationResultV1& result,
    const vfdual::HostPairGenerationCredentialErrorCodeV1 code) {
    VFDUAL_TEST_REQUIRE(!result.succeeded());
    VFDUAL_TEST_REQUIRE(!result.credential.has_value());
    VFDUAL_TEST_REQUIRE(result.error.code == code);
}

void verifies_current_and_previous_server_contract_tokens() {
    auto verifier = make_verifier();
    const auto current = verifier->verify(kCurrentToken, expected(), kNowEpoch);
    VFDUAL_TEST_REQUIRE(current.succeeded());
    const auto& claims = *current.credential;
    VFDUAL_TEST_REQUIRE(claims.key_id() == kCurrentKeyId);
    VFDUAL_TEST_REQUIRE(claims.allocation_request_id() == "allocation.req:host-1");
    VFDUAL_TEST_REQUIRE(claims.pair_id() == repeat('1', 32U));
    VFDUAL_TEST_REQUIRE(claims.entitlement_id() == repeat('2', 32U));
    VFDUAL_TEST_REQUIRE(claims.binding_id() == repeat('3', 32U));
    VFDUAL_TEST_REQUIRE(claims.binding_revision() == 3);
    VFDUAL_TEST_REQUIRE(claims.revocation_version() == 4);
    VFDUAL_TEST_REQUIRE(claims.generation() == 7);
    VFDUAL_TEST_REQUIRE(claims.connection_id() == 8);
    VFDUAL_TEST_REQUIRE(claims.host_identity_spki_sha256() == repeat('4', 64U));
    VFDUAL_TEST_REQUIRE(claims.android_identity_spki_sha256() == repeat('5', 64U));
    VFDUAL_TEST_REQUIRE(claims.transcript_proposal_sha256() == repeat('6', 64U));
    VFDUAL_TEST_REQUIRE(claims.credential_nonce() == repeat('7', 64U));
    VFDUAL_TEST_REQUIRE(claims.issued_at_epoch() == kNowEpoch);
    VFDUAL_TEST_REQUIRE(claims.not_before_epoch() == kNowEpoch);
    VFDUAL_TEST_REQUIRE(claims.expires_at_epoch() == kNowEpoch + 15);
    VFDUAL_TEST_REQUIRE(lower_hex(claims.token_sha256()) == kCurrentTokenSha256);

    const auto previous = verifier->verify(
        kPreviousToken, expected(), kNowEpoch + 1);
    VFDUAL_TEST_REQUIRE(previous.succeeded());
    VFDUAL_TEST_REQUIRE(previous.credential->key_id() == kPreviousKeyId);
}

void rejects_tampering_context_rollback_and_time_boundaries() {
    auto verifier = make_verifier();
    std::string tampered{kCurrentToken};
    tampered.back() = tampered.back() == 'A' ? 'B' : 'A';
    require_error(
        verifier->verify(tampered, expected(), kNowEpoch),
        vfdual::HostPairGenerationCredentialErrorCodeV1::token_invalid);

    auto stale_generation = expected();
    stale_generation.generation += 1;
    require_error(
        verifier->verify(kCurrentToken, stale_generation, kNowEpoch),
        vfdual::HostPairGenerationCredentialErrorCodeV1::token_invalid);

    auto wrong_proposal = expected();
    wrong_proposal.transcript_proposal_sha256 = repeat('8', 64U);
    require_error(
        verifier->verify(kCurrentToken, wrong_proposal, kNowEpoch),
        vfdual::HostPairGenerationCredentialErrorCodeV1::token_invalid);

    require_error(
        verifier->verify(kCurrentToken, expected(), kNowEpoch + 15),
        vfdual::HostPairGenerationCredentialErrorCodeV1::token_invalid);
    require_error(
        verifier->verify(kCurrentToken, expected(), kNowEpoch - 3),
        vfdual::HostPairGenerationCredentialErrorCodeV1::token_invalid);
}

void rejects_invalid_sources_keyrings_and_cross_purpose_reuse() {
    auto verifier = make_verifier();
    auto invalid = expected();
    invalid.android_identity_spki_sha256 = invalid.host_identity_spki_sha256;
    require_error(
        verifier->verify(kCurrentToken, invalid, kNowEpoch),
        vfdual::HostPairGenerationCredentialErrorCodeV1::source_invalid);
    require_error(
        verifier->verify("not-a-token", expected(), kNowEpoch),
        vfdual::HostPairGenerationCredentialErrorCodeV1::token_invalid);

    using PublicKey = vfdual::HostPairGenerationCredentialTestPublicKeyV1;
    const std::array<PublicKey, 0U> no_keys{};
    const std::array<PublicKey, 0U> no_other{};
    const auto empty = vfdual::HostPairGenerationCredentialV1Verifier::
        create_for_test_fixture_keyring(no_keys, no_other);
    VFDUAL_TEST_REQUIRE(!empty.succeeded());
    VFDUAL_TEST_REQUIRE(
        empty.error.code ==
        vfdual::HostPairGenerationCredentialErrorCodeV1::key_invalid);

    const std::array duplicate_keys{
        PublicKey{kCurrentPublicSpkiDer},
        PublicKey{kCurrentPublicSpkiDer},
    };
    const auto duplicate = vfdual::HostPairGenerationCredentialV1Verifier::
        create_for_test_fixture_keyring(duplicate_keys, no_other);
    VFDUAL_TEST_REQUIRE(!duplicate.succeeded());

    const std::array pair_keys{PublicKey{kCurrentPublicSpkiDer}};
    const std::array other_purpose{PublicKey{kCurrentPublicSpkiDer}};
    const auto reused = vfdual::HostPairGenerationCredentialV1Verifier::
        create_for_test_fixture_keyring(pair_keys, other_purpose);
    VFDUAL_TEST_REQUIRE(!reused.succeeded());

    const auto production = vfdual::HostPairGenerationCredentialV1Verifier::
        create_from_build_pinned_keyring();
    if constexpr (vfdual::build::
            kPairGenerationCredentialPublicPemBase64.empty()) {
        VFDUAL_TEST_REQUIRE(!production.succeeded());
        VFDUAL_TEST_REQUIRE(
            production.error.code ==
            vfdual::HostPairGenerationCredentialErrorCodeV1::key_invalid);
    } else {
        VFDUAL_TEST_REQUIRE(production.succeeded());
    }
}

void verifies_sanitized_stable_error_names() {
    VFDUAL_TEST_REQUIRE(
        std::string_view{
            vfdual::host_pair_generation_credential_error_code_name_v1(
                vfdual::HostPairGenerationCredentialErrorCodeV1::
                    source_invalid)} ==
        "pair_generation_credential_source_invalid");
    VFDUAL_TEST_REQUIRE(
        std::string_view{
            vfdual::host_pair_generation_credential_error_code_name_v1(
                vfdual::HostPairGenerationCredentialErrorCodeV1::
                    token_invalid)} ==
        "pair_generation_credential_invalid");
}

}  // namespace

int main() {
    verifies_current_and_previous_server_contract_tokens();
    rejects_tampering_context_rollback_and_time_boundaries();
    rejects_invalid_sources_keyrings_and_cross_purpose_reuse();
    verifies_sanitized_stable_error_names();
    return EXIT_SUCCESS;
}
