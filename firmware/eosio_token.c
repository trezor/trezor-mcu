#include "eosio_token.h"

#include "eos.h"
#include "gettext.h"
#include "protect.h"

#include "messages-eos.pb.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#define CHECK_COMMON(ACTION) \
    do { \
        CHECK_PARAM_RET(common->account == EOS_eosio_token, \
                        _("Incorrect account name"), false); \
        CHECK_PARAM_RET(common->name == (ACTION), \
                        _("Incorrect action name"), false); \
    } while(0)

bool eos_compileActionTransfer(const EosActionCommon *common,
                               const EosActionTransfer *action) {
    CHECK_COMMON(EOS_Transfer);

    CHECK_PARAM_RET(action->has_quantity, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_sender, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_receiver, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_memo, _("Required field missing"), false);

    size_t memo_len = strlen(action->memo);

    if (256 < memo_len) {
        fsm_sendFailure(FailureType_Failure_DataError, _("Memo too long"));
        eos_signingAbort();
        layoutHome();
        return false;
    }

    char asset[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->quantity, asset),
                    _("Invalid asset format"), false);

    char sender[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->sender, sender),
                    _("Invalid name"), false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    _("Invalid name"), false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Transfer"),
        _("Do you want to send"),
        asset,
        _("from"),
        sender,
        _("to"),
        receiver);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    layoutConfirmMemo((const uint8_t*)action->memo, memo_len);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    uint32_t size = 8 + 8 + 16 + eos_hashUInt(NULL, memo_len) + memo_len;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->sender, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->quantity),
                    _("Cannot compile asset: quantity"), false);

    eos_hashUInt(&hasher_preimage, memo_len);
    hasher_Update(&hasher_preimage, (const uint8_t*)action->memo, memo_len);

    return true;
}

