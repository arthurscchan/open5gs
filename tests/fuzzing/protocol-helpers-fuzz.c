#include <stdint.h>
#include <string.h>

#include "fuzzing.h"
#include "ogs-proto.h"
#include "ogs-nas-common.h"

#define kMinInputLength 1
#define kMaxInputLength 257

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    char *input;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1] = {0};
    bool imsi_supi = false;
    uint8_t selector;
    size_t payload_size;

    if (Size < kMinInputLength || Size > kMaxInputLength)
        return 0;

    if (!initialized) {
        initialize();
        ogs_log_set_mask_level("core", OGS_LOG_NONE);
        ogs_log_install_domain(&__ogs_nas_domain, "nas", OGS_LOG_NONE);
    }

    selector = Data[0] % 4;
    payload_size = Size - 1;

    if (selector == 3) {
        ogs_nas_mobile_identity_imeisv_t identity;
        char imeisv_bcd[OGS_MAX_IMEISV_BCD_LEN + 1] = {0};

        if (payload_size != sizeof(identity) + 1)
            return 0;

        memcpy(&identity, Data + 2, sizeof(identity));
        ogs_nas_imeisv_to_bcd(&identity, Data[1], imeisv_bcd);
        return 0;
    }

    input = ogs_malloc(payload_size + 1);
    if (!input)
        return 0;

    memcpy(input, Data + 1, payload_size);
    input[payload_size] = '\0';

    switch (selector) {
    case 0:
        ogs_dnn_oi_from_fqdn(input);
        ogs_plmn_id_mcc_from_fqdn(input);
        ogs_plmn_id_mnc_from_fqdn(input);
        break;
    case 1:
        ogs_supi_to_imsi_bcd(input, imsi_bcd, &imsi_supi);
        break;
    case 2:
        ogs_pei_is_valid(input);
        break;
    }

    ogs_free(input);
    return 0;
}
