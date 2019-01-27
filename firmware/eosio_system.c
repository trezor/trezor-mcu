#include "eosio_system.h"

#include "eos.h"
#include "util.h"
#include "gettext.h"
#include "protect.h"

#include "messages-eos.pb.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#define CHECK_COMMON(ACTION) \
    do { \
        CHECK_PARAM_RET(common->account == EOS_eosio || \
                        common->account == EOS_eosio_token, \
                        "Incorrect account name", false); \
        CHECK_PARAM_RET(common->name == (ACTION), \
                        "Incorrect action name", false); \
    } while(0)

bool eos_compileActionDelegate(const EosActionCommon *common,
                               const EosActionDelegate *action) {
    CHECK_COMMON(EOS_DelegateBW);

    CHECK_PARAM_RET(action->has_sender, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_receiver, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_cpu_quantity, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_net_quantity, _("Required field missing"), false);

    char sender[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->sender, sender),
                    _("Invalid name"), false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    _("Invalid name"), false);

    char cpu[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->cpu_quantity, cpu),
                    "Invalid asset format", false);

    char net[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->net_quantity, net),
                    "Invalid asset format", false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        (action->has_transfer && action->transfer) ? _("Delegate") : _("Transfer"),
        cpu, net,
        _("From:"), sender,
        _("To:"), receiver);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16 + 16 + 1;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->sender, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->net_quantity),
                    "Cannot compile asset: net_quantity", false);

    CHECK_PARAM_RET(eos_compileAsset(&action->cpu_quantity),
                    "Cannot compile asset: cpu_quantity", false);

    uint8_t is_transfer = (action->has_transfer && action->transfer) ? 1 : 0;
    hasher_Update(&hasher_preimage, &is_transfer, 1);

    return true;
}

bool eos_compileActionUndelegate(const EosActionCommon *common,
                                 const EosActionUndelegate *action) {
    CHECK_COMMON(EOS_UndelegateBW);

    CHECK_PARAM_RET(action->has_sender, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_receiver, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_cpu_quantity, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_net_quantity, _("Required field missing"), false);

    char sender[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->sender, sender),
                    _("Invalid name"), false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    _("Invalid name"), false);

    char cpu[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->cpu_quantity, cpu),
                    "Invalid asset format", false);

    char net[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->net_quantity, net),
                    "Invalid asset format", false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Revoke delegate"),
        cpu, net,
        _("From:"), sender,
        _("To:"), receiver);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16 + 16;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->sender, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->net_quantity),
                    "Cannot compile asset: net_quantity", false);

    CHECK_PARAM_RET(eos_compileAsset(&action->cpu_quantity),
                    "Cannot compile asset: cpu_quantity", false);

    return true;
}

bool eos_compileActionRefund(const EosActionCommon *common,
                             const EosActionRefund *action) {
    CHECK_COMMON(EOS_Refund);

    CHECK_PARAM_RET(action->has_owner, _("Required field missing"), false);

    char owner[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->owner, owner),
                    _("Invalid name"), false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Refund"),
        _("Do you want to"),
        _("reclaim unstaked"),
        _("tokens from your"),
        owner,
        _("account ?"),
        NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->owner, 8);

    return true;
}

bool eos_compileActionBuyRam(const EosActionCommon *common,
                             const EosActionBuyRam *action) {
    CHECK_COMMON(EOS_BuyRam);

    CHECK_PARAM_RET(action->has_payer, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_receiver, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_quantity, _("Required field missing"), false);

    char payer[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->payer, payer),
                    _("Invalid name"), false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    _("Invalid name"), false);

    char quantity[EOS_ASSET_STR_SIZE];
    CHECK_PARAM_RET(eos_formatAsset(&action->quantity, quantity),
                    "Invalid asset format", false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Buyram"),
        _("Buy"),
        quantity,
        _("with"),
        payer,
        _("for"),
        receiver);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    uint32_t size = 8 + 8 + 16;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->payer, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);

    CHECK_PARAM_RET(eos_compileAsset(&action->quantity),
                    "Cannot compile asset: quantity", false);

    return true;
}

bool eos_compileActionBuyRamBytes(const EosActionCommon *common,
                                  const EosActionBuyRamBytes *action) {
    CHECK_COMMON(EOS_BuyRamBytes);

    CHECK_PARAM_RET(action->has_payer, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_receiver, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_bytes, _("Required field missing"), false);

    char payer[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->payer, payer),
                    _("Invalid name"), false);

    char receiver[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->receiver, receiver),
                    _("Invalid name"), false);

    char quantity[10+1+5+1];
    snprintf(quantity, sizeof(quantity), "%" PRIu32 " bytes", action->bytes);
    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Buyram"),
        _("Buy"),
        quantity,
        _("with"),
        payer,
        _("for"),
        receiver);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    uint32_t size = 8 + 8 + 4;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->payer, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->receiver, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->bytes, 4);

    return true;
}

bool eos_compileActionSellRam(const EosActionCommon *common,
                              const EosActionSellRam *action) {
    CHECK_COMMON(EOS_SellRam);

    CHECK_PARAM_RET(action->has_account, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_bytes, _("Required field missing"), false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    _("Invalid name"), false);

    char quantity[10+1+5+1];
    snprintf(quantity, sizeof(quantity), "%" PRIu64 " bytes", action->bytes);
    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Sellram"),
        _("Sell"),
        quantity,
        _("from"),
        account,
        _("at market price?"),
        NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    uint32_t size = 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->bytes, 8);

    return true;
}

bool eos_compileActionVoteProducer(const EosActionCommon *common,
                                   const EosActionVoteProducer *action) {
    CHECK_COMMON(EOS_VoteProducer);

    CHECK_PARAM_RET(action->has_voter, _("Required field missing"), false);

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    if (action->has_proxy && action->proxy != 0) {
        char voter[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->voter, voter),
                        _("Invalid name"), false);

        char proxy[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->proxy, proxy),
                        _("Invalid name"), false);

        layoutDialogSwipe(
            &bmp_icon_question,
            _("Cancel"),
            _("Confirm"),
            _("Vote Producer"),
            _("Using"),
            voter,
            _("do you want to"),
            _("vote for"),
            proxy,
            _("as your proxy?"));
        if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            eos_signingAbort();
            layoutHome();
            return false;
        }

        uint32_t size = 8 + 8 + eos_hashUInt(NULL, 0) + 0;
        eos_hashUInt(&hasher_preimage, size);

        hasher_Update(&hasher_preimage, (const uint8_t*)&action->voter, 8);
        hasher_Update(&hasher_preimage, (const uint8_t*)&action->proxy, 8);

        eos_hashUInt(&hasher_preimage, /*producers_count=*/0);

    } else if (action->producers_count != 0) {
        // Sanity check, which the contract also enforces
        for (size_t i = 1; i < action->producers_count; i++) {
            CHECK_PARAM_RET(action->producers[i - 1] < action->producers[i],
                            _("Producer votes must be unique and sorted"), false);
        }

        char voter[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->voter, voter),
                        _("Invalid name"), false);

        layoutDialogSwipe(
            &bmp_icon_question,
            _("Cancel"),
            _("Confirm"),
            _("Vote Producers"),
            _("Using"),
            voter,
            _("do you want to"),
            _("vote for the"),
            _("following producers?"),
            NULL);
        if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            eos_signingAbort();
            layoutHome();
            return false;
        }

        const size_t chunk_size = 6;
        char producers[chunk_size][EOS_NAME_STR_SIZE];
        const uint8_t pages = (uint8_t)((action->producers_count / chunk_size) + 1) + 1;

        for (size_t i = 0; i < action->producers_count; i += chunk_size) {
            memset(producers, 0, sizeof(producers));
            for (size_t p = 0; p < chunk_size && p + i < action->producers_count; p++) {
                CHECK_PARAM_RET(eos_formatName(action->producers[p + i], producers[p]),
                                _("Invalid name"), false);
            }

            uint8_t page_no = (uint8_t)((i / chunk_size) + 1) + 1;
            char title[14 + 3 + 1 + 3 + 1];
            snprintf(title, sizeof(title),
                     _("Vote Producer %" PRIu8 "/%" PRIu8),
                     page_no, pages);
            layoutDialogSwipe(
                &bmp_icon_question,
                _("Cancel"),
                _("Confirm"),
                title,
                i * chunk_size + 0 < action->producers_count ? producers[0] : NULL,
                i * chunk_size + 1 < action->producers_count ? producers[1] : NULL,
                i * chunk_size + 2 < action->producers_count ? producers[2] : NULL,
                i * chunk_size + 3 < action->producers_count ? producers[3] : NULL,
                i * chunk_size + 4 < action->producers_count ? producers[4] : NULL,
                i * chunk_size + 5 < action->producers_count ? producers[5] : NULL);
            if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
                eos_signingAbort();
                layoutHome();
                return false;
            }
        }

        uint32_t size = 8 + 8 + eos_hashUInt(NULL, action->producers_count) +
                        8 * action->producers_count;
        eos_hashUInt(&hasher_preimage, size);

        hasher_Update(&hasher_preimage, (const uint8_t*)&action->voter, 8);
        hasher_Update(&hasher_preimage, (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);

        eos_hashUInt(&hasher_preimage, action->producers_count);
        for (size_t p = 0; p < action->producers_count; p++) {
            hasher_Update(&hasher_preimage, (const uint8_t*)&action->producers[p], 8);
        }
    } else {
        char voter[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(action->voter, voter),
                        _("Invalid name"), false);

        layoutDialogSwipe(
            &bmp_icon_question,
            _("Cancel"),
            _("Confirm"),
            _("Vote Producer"),
            _("Using"),
            voter,
            _("do you want to"),
            _("cancel your vote?"),
            NULL,
            NULL);
        if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            eos_signingAbort();
            layoutHome();
            return false;
        }

        uint32_t size = 8 + 8 + eos_hashUInt(NULL, 0) + 0;
        eos_hashUInt(&hasher_preimage, size);

        hasher_Update(&hasher_preimage, (const uint8_t*)&action->voter, 8);
        hasher_Update(&hasher_preimage, (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);
        eos_hashUInt(&hasher_preimage, /*producers_count=*/0);
    }

    return true;
}

static size_t eos_hashAuthorization(Hasher *h, const EosAuthorization *auth) {
    size_t count = 0;

    count += 4;
    if (h) hasher_Update(h, (const uint8_t*)&auth->threshold, 4);

    count += eos_hashUInt(h, auth->keys_count);
    for (size_t i = 0; i < auth->keys_count; i++) {
        const EosAuthorizationKey *auth_key = &auth->keys[i];

        count += eos_hashUInt(NULL, auth_key->type);
        if (h) eos_hashUInt(h, auth_key->type);

        count += auth_key->key.size;
        if (h) hasher_Update(h, auth_key->key.bytes, auth_key->key.size);

        count += 2;
        if (h) hasher_Update(h, (const uint8_t*)&auth_key->weight, 2);
    }

    count += eos_hashUInt(h, auth->accounts_count);
    for (size_t i = 0; i < auth->accounts_count; i++) {
        count += 8;
        if (h) hasher_Update(h, (const uint8_t*)&auth->accounts[i].account.actor, 8);

        count += 8;
        if (h) hasher_Update(h, (const uint8_t*)&auth->accounts[i].account.permission, 8);

        count += 2;
        if (h) hasher_Update(h, (const uint8_t*)&auth->accounts[i].weight, 2);
    }

    count += eos_hashUInt(h, auth->waits_count);
    for (size_t i = 0; i < auth->accounts_count; i++) {
        count += 4;
        if (h) hasher_Update(h, (const uint8_t*)&auth->waits[i].wait_sec, 4);

        count += 2;
        if (h) hasher_Update(h, (const uint8_t*)&auth->waits[i].weight, 2);
    }

    return count;
}

bool eos_compileAuthorization(const char *title, const EosAuthorization *auth) {
    CHECK_PARAM_RET(auth->has_threshold, _("Required field missing"), false);

    char threshold[10 + 2 + 1];
    snprintf(threshold, sizeof(threshold), "%" PRIu32 "?", auth->threshold);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        title,
        _("Require an"),
        _("authorization"),
        _("threshold of"),
        threshold,
        NULL,
        NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    for (size_t i = 0; i < auth->keys_count; i++) {
        const EosAuthorizationKey *auth_key = &auth->keys[i];

        CHECK_PARAM_RET(auth_key->has_weight, _("Required field missing"), false);
        CHECK_PARAM_RET(auth_key->key.size == 33, _("Required field missing"), false);

        char pubkey[65];
        if (auth_key->key.size != 33 ||
            !eos_publicKeyToWif(auth_key->key.bytes, pubkey, sizeof(pubkey))) {
            fsm_sendFailure(FailureType_Failure_DataError, _("Cannot encode pubkey"));
            eos_signingAbort();
            layoutHome();
            return false;
        }

        char key_idx[11 + 3 + 1];
        snprintf(key_idx, sizeof(key_idx), "Auth Key: #%" PRIu8, (uint8_t)(i + 1));

        char weight[7 + 5 + 1];
        snprintf(weight, sizeof(weight), "Weight: %" PRIu16, (uint16_t)auth_key->weight);

        const char **pubkey_parts = split_message((const uint8_t*)pubkey, sizeof(pubkey), 20);

        layoutDialogSwipe(
            &bmp_icon_question,
            _("Cancel"),
            _("Confirm"),
            title,
            key_idx,
            weight,
            pubkey_parts[0],
            pubkey_parts[1],
            pubkey_parts[2],
            pubkey_parts[3]);
        if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            eos_signingAbort();
            layoutHome();
            return false;
        }
    }

    for (size_t i = 0; i < auth->accounts_count; i++) {
        CHECK_PARAM_RET(auth->accounts[i].account.has_actor, _("Required field missing"), false);
        CHECK_PARAM_RET(auth->accounts[i].account.has_permission, _("Required field missing"), false);

        char account[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(auth->accounts[i].account.actor, account),
                        _("Invalid name"), false);

        char permission[EOS_NAME_STR_SIZE];
        CHECK_PARAM_RET(eos_formatName(auth->accounts[i].account.permission, permission),
                        _("Invalid name"), false);

        char account_str[10 + 3 + 1 + 1];
        snprintf(account, sizeof(account), "Account: #%" PRIu8 ":", (uint8_t)(i + 1));

        char weight[13 + 5 + 1];
        snprintf(weight, sizeof(weight), "with weight: %" PRIu16, (uint16_t)(auth->accounts[i].weight));

        layoutDialogSwipe(
            &bmp_icon_question,
            _("Cancel"),
            _("Confirm"),
            title,
            account_str,
            _("Assign"),
            permission,
            _("permission to"),
            account,
            weight);
        if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            eos_signingAbort();
            layoutHome();
            return false;
        }
    }

    for (size_t i = 0; i < auth->waits_count; i++) {
        CHECK_PARAM_RET(auth->waits[i].has_wait_sec, _("Required field missing"), false);

        char wait[7 + 3 + 1];
        snprintf(wait, sizeof(wait), "Delay #%" PRIu8, (uint8_t)(i + 1));

        char duration[10 + 1 + 1];
        snprintf(duration, sizeof(duration), "%" PRIu32 "s", auth->waits[i].wait_sec);

        char weight[5 + 1 + 1];
        snprintf(weight, sizeof(weight), "%" PRIu16 "?", (uint16_t)auth->waits[i].weight);

        layoutDialogSwipe(
            &bmp_icon_question,
            _("Cancel"),
            _("Confirm"),
            title,
            wait,
            _("Require a delay of"),
            duration,
            _("with weight"),
            weight,
            NULL);
        if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            eos_signingAbort();
            layoutHome();
            return false;
        }
    }

    if (!eos_hashAuthorization(&hasher_preimage, auth))
        return false;

    return true;
}

bool eos_compileActionUpdateAuth(const EosActionCommon *common,
                                 const EosActionUpdateAuth *action) {
    CHECK_COMMON(EOS_UpdateAuth);

    CHECK_PARAM_RET(action->has_account, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_permission, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_parent, _("Required field missing"), false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    _("Invalid name"), false);

    char permission[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->permission, permission),
                    _("Invalid name"), false);

    char parent[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->parent, parent),
                    _("Invalid name"), false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Update auth for"),
        account,
        _("with"),
        permission,
        _("permission and"),
        parent,
        _("parent"));
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    size_t auth_size = eos_hashAuthorization(NULL, &action->auth);
    CHECK_PARAM_RET(0 < auth_size, _("EosAuthorization hash failed"), false);

    size_t size = 8 + 8 + 8 + auth_size;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->permission, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->parent, 8);

    char title[12 + 1 + 12 + 1];
    snprintf(title, sizeof(title), "%s@%s", account, permission);
    if (!eos_compileAuthorization(title, &action->auth))
        return false;

    return true;
}

bool eos_compileActionDeleteAuth(const EosActionCommon *common,
                                 const EosActionDeleteAuth *action) {
    CHECK_COMMON(EOS_DeleteAuth);

    CHECK_PARAM_RET(action->has_account, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_permission, _("Required field missing"), false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    _("Invalid name"), false);

    char permission[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->permission, permission),
                    _("Invalid name"), false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Delete auth"),
        _("Remove"),
        permission,
        _("permission from"),
        account,
        _("?"),
        NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    size_t size = 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->permission, 8);

    return true;
}

bool eos_compileActionLinkAuth(const EosActionCommon *common,
                               const EosActionLinkAuth *action) {
    CHECK_COMMON(EOS_LinkAuth);

    CHECK_PARAM_RET(action->has_account, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_code, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_type, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_requirement, _("Required field missing"), false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    _("Invalid name"), false);

    char code[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->code, code),
                    _("Invalid name"), false);

    char type[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->type, type),
                    _("Invalid name"), false);

    char requirement[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->requirement, requirement),
                    _("Invalid name"), false);

    char whom[12 + 1 + 12 + 1 + 1];
    snprintf(whom, sizeof(whom), "%s@%s?", account, requirement);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Link Auth"),
        _("Grant"),
        type,
        _("permission for the"),
        code,
        _("contract to"),
        whom);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    size_t size = 8 + 8 + 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->code, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->type, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->requirement, 8);

    return true;
}

bool eos_compileActionUnlinkAuth(const EosActionCommon *common,
                                 const EosActionUnlinkAuth *action) {
    CHECK_COMMON(EOS_UnlinkAuth);

    CHECK_PARAM_RET(action->has_account, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_code, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_type, _("Required field missing"), false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->account, account),
                    _("Invalid name"), false);

    char code[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->code, code),
                    _("Invalid name"), false);

    char type[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->type, type),
                    _("Invalid name"), false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("Unlink Auth"),
        _("Unlink"),
        account,
        _("from auth to"),
        code,
        _("for"),
        type);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    size_t size = 8 + 8 + 8;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->account, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->code, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->type, 8);

    return true;
}

bool eos_compileActionNewAccount(const EosActionCommon *common,
                                 const EosActionNewAccount *action) {
    CHECK_COMMON(EOS_NewAccount);

    CHECK_PARAM_RET(action->has_creator, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_name, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_owner, _("Required field missing"), false);
    CHECK_PARAM_RET(action->has_active, _("Required field missing"), false);

    char creator[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->creator, creator),
                    _("Invalid name"), false);

    char name[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(action->name, name),
                    _("Invalid name"), false);

    layoutDialogSwipe(
        &bmp_icon_question,
        _("Cancel"),
        _("Confirm"),
        _("New Account"),
        _("Using"),
        creator,
        _("create new account"),
        name,
        _("?"),
        NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        eos_signingAbort();
        layoutHome();
        return false;
    }

    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    _("Cannot compile ActionCommon"), false);

    size_t owner_size = eos_hashAuthorization(NULL, &action->owner);
    CHECK_PARAM_RET(0 < owner_size, _("EosAuthorization hash failed"), false);

    size_t active_size = eos_hashAuthorization(NULL, &action->active);
    CHECK_PARAM_RET(0 < active_size, _("EosAuthorization hash failed"), false);

    size_t size = 8 + 8 + owner_size + active_size;
    eos_hashUInt(&hasher_preimage, size);

    hasher_Update(&hasher_preimage, (const uint8_t*)&action->creator, 8);
    hasher_Update(&hasher_preimage, (const uint8_t*)&action->name, 8);

    char title[12 + 1 + 6 + 1];
    snprintf(title, sizeof(title), "%s@owner", name);
    if (!eos_compileAuthorization(title, &action->owner))
        return false;

    snprintf(title, sizeof(title), "%s@active", name);
    if (!eos_compileAuthorization(title, &action->active))
        return false;

    return true;
}
