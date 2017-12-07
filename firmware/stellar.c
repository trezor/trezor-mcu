/*
 * This file is part of the TREZOR project.
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Stellar signing has the following workflow:
 *  1. Client sends first 1024 bytes of the transaction
 *  2. Trezor parses the transaction header and confirms the details with the user
 *  3. Trezor responds to the client with an offset for where to send the next chunk of bytes
 *  4. Client sends next 1024 bytes starting at <offset>
 *  5. Trezor parses and confirms the next operation
 *  6. Trezor responds with either an offset for the next operation or a signature
 */

#include <stdbool.h>
#include <time.h>
#include "messages.h"
#include "messages.pb.h"
#include "stellar.h"
#include "bip32.h"
#include "crypto.h"
#include "layout2.h"
#include "gettext.h"
#include "bignum.h"
#include "oled.h"
#include "base32.h"
#include "storage.h"
#include "fsm.h"
#include "protect.h"
#include "util.h"

static bool stellar_signing = false;
static StellarTransaction stellar_activeTx;

/*
 * Starts the signing process and parses the transaction header
 */
void stellar_signingInit(StellarSignTx *msg)
{
    const uint8_t tx_type_bytes[4] = { 0x00, 0x00, 0x00, 0x02 };
    stellar_signing = true;
    memset(&stellar_activeTx, 0, sizeof(StellarTransaction));

    // Public key comes from deriving the specified account path (this should match what's in the XDR)
    uint8_t bytes_pubkey[32];
    stellar_getPubkeyAtIndex(msg->index, bytes_pubkey, sizeof(bytes_pubkey));
    memcpy(&(stellar_activeTx.account_id), bytes_pubkey, sizeof(stellar_activeTx.account_id));
    memcpy(&(stellar_activeTx.account_index), &(msg->index), sizeof(stellar_activeTx.account_index));

    // Skip account ID type since it's always 0
    stellar_activeTx.xdr_offset += 4;

    // Skip public key bytes since we derive this above
    stellar_activeTx.xdr_offset += 32;

    // Fee (4 byte unsigned int)
    memcpy(&(stellar_activeTx.fee), msg->header_xdr.bytes + stellar_activeTx.xdr_offset, 4);
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE32(stellar_activeTx.fee, stellar_activeTx.fee);
#endif
    stellar_activeTx.xdr_offset += 4;

    // Sequence number (8 byte unsigned int)
    memcpy(&(stellar_activeTx.sequence_number), msg->header_xdr.bytes + stellar_activeTx.xdr_offset, 8);
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE64(stellar_activeTx.sequence_number, stellar_activeTx.sequence_number);
#endif
    stellar_activeTx.xdr_offset += 8;

    // Time bounds are an optional union which is encoded as:
    //  4 bytes - boolean (whether there is data)
    //  8 bytes - if data, then this is the first timestamp
    //  8 bytes - if data, then this is the second timestamp
    uint8_t has_timebounds = stellar_xdr_read_bool(msg->header_xdr.bytes, &(stellar_activeTx.xdr_offset));
    if (has_timebounds) {
        memcpy(&(stellar_activeTx.timebound_min), msg->header_xdr.bytes + stellar_activeTx.xdr_offset, 8);
#if BYTE_ORDER == LITTLE_ENDIAN
        REVERSE64(stellar_activeTx.timebound_min, stellar_activeTx.timebound_min);
#endif
        stellar_activeTx.xdr_offset += 8;

        memcpy(&(stellar_activeTx.timebound_max), msg->header_xdr.bytes + stellar_activeTx.xdr_offset, 8);
#if BYTE_ORDER == LITTLE_ENDIAN
        REVERSE64(stellar_activeTx.timebound_max, stellar_activeTx.timebound_max);
#endif
        stellar_activeTx.xdr_offset += 8;
    }

    // Memo type (4 bytes)
    stellar_activeTx.memo_type = stellar_xdr_read_uint32(msg->header_xdr.bytes, &(stellar_activeTx.xdr_offset));

    // Memo (based on type)
    switch (stellar_activeTx.memo_type) {
        // None, nothing else to do
        case 0:
            break;
        // Text: 4 bytes (size) + up to 28 bytes
        case 1:
            stellar_xdr_read_string(stellar_activeTx.memo, msg->header_xdr.bytes, &(stellar_activeTx.xdr_offset));
            break;
        // ID (8 bytes, uint64)
        case 2:
            memcpy(&(stellar_activeTx.memo), msg->header_xdr.bytes + stellar_activeTx.xdr_offset, 8);
            stellar_activeTx.xdr_offset += 8;
            break;
        // Hash and return are the same data structure (32 byte tx hash)
        case 3:
        case 4:
            memcpy(&(stellar_activeTx.memo), msg->header_xdr.bytes + stellar_activeTx.xdr_offset, 32);
            stellar_activeTx.xdr_offset += 32;
            break;
        default:
            break;
    }

    // Number of operations (4 bytes) (this is encoded as part of the operations array but consider it part of the header)
    stellar_activeTx.num_operations = stellar_xdr_read_uint32(msg->header_xdr.bytes, &(stellar_activeTx.xdr_offset));

    // Header parsing finished, start calculating hash for the initial data

    // Initialize signing context
    sha256_Init(&(stellar_activeTx.sha256_ctx));

    // Calculate sha256 for network passphrase
    // max length defined in messages.options
    uint8_t network_hash[32];
    sha256_Raw((uint8_t *)msg->network_passphrase, strnlen(msg->network_passphrase, 1024), network_hash);

    // Determine what type of network this transaction is for
    if (strncmp("Public Global Stellar Network ; September 2015", msg->network_passphrase, 1024) == 0) {
        stellar_activeTx.network_type = 1;
    }
    else if (strncmp("Test SDF Network ; September 2015", msg->network_passphrase, 1024) == 0) {
        stellar_activeTx.network_type = 2;
    }
    else {
        stellar_activeTx.network_type = 3;
    }

    // Start building what will be signed:
    // sha256 of:
    //  sha256(network passphrase)
    //  4-byte unsigned big-endian int type constant (2 for tx)
    //  remaining bytes are operations added in subsequent messages
    sha256_Update(&(stellar_activeTx.sha256_ctx), network_hash, sizeof(network_hash));

    sha256_Update(&(stellar_activeTx.sha256_ctx), tx_type_bytes, sizeof(tx_type_bytes));

    // Add the bytes of XDR that we've processed so far
    // stellar_activeTx.xdr_offset tracks how large the header is
    sha256_Update(&(stellar_activeTx.sha256_ctx), msg->header_xdr.bytes, stellar_activeTx.xdr_offset);
}

/*
 * Adds an operation to the current transaction by parsing the StellarTxOpAck message
 */
void stellar_addOperation(StellarTxOpAck *msg)
{
    uint32_t offset = 0;
    uint32_t op_type;

    if (!stellar_signing) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Not in Stellar signing mode"));
        layoutHome();
        return;
    }

    // Source account is optional (XDR booleans are 4 bytes)
    // Prompt the user for additional verification if one is present
    uint8_t has_source_account = stellar_xdr_read_bool(msg->xdr.bytes + offset, &offset);
    if (has_source_account) {
        uint8_t op_src_account[32];
        stellar_xdr_read_address(op_src_account, msg->xdr.bytes + offset, &offset);
        const char **str_addr_rows = stellar_lineBreakAddress(op_src_account);

        stellar_layoutTransactionDialog(
            _("Op src account OK?"),
            NULL,
            str_addr_rows[0],
            str_addr_rows[1],
            str_addr_rows[2]
        );
        if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
            stellar_signingAbort();
            return;
        }
    }

    // Operation type (4 byte unsigned int)
    op_type = stellar_xdr_read_uint32(msg->xdr.bytes, &offset);

    // PAYMENT
    if (op_type == 1) {
        stellar_confirmPaymentOp(msg->xdr.bytes, &offset);
    }

    // Update the hash to be signed with data in this operation
    sha256_Update(&(stellar_activeTx.sha256_ctx), msg->xdr.bytes, offset);

    // If the last operation was confirmed, update the hash with 4 null bytes.
    // These are for the currently reserved union at the end of the transaction envelope
    if (stellar_allOperationsConfirmed()) {
        uint8_t empty_bytes[4] = { 0x00, 0x00, 0x00, 0x00 };
        sha256_Update(&(stellar_activeTx.sha256_ctx), empty_bytes, sizeof(empty_bytes));
    }
}

void stellar_confirmPaymentOp(uint8_t *bytestream, uint32_t *offset)
{
    uint8_t pubaddr_bytes[32];
    stellar_xdr_read_address(pubaddr_bytes, bytestream, offset);
    const char **str_addr_rows = stellar_lineBreakAddress(pubaddr_bytes);

    // To: G...
    char str_to[32];
    strlcpy(str_to, _("To: "), sizeof(str_to));
    strlcat(str_to, str_addr_rows[0], sizeof(str_to));

    // Asset
    char str_asset_row[32];
    char str_asset_name[12 + 1];
    // Full asset issuer string
    char str_asset_issuer[56+1];
    // truncated asset issuer, G1234
    char str_asset_issuer_trunc[5 + 1];
    uint8_t issuer_bytes[32];

    uint32_t asset_type = stellar_xdr_read_uint32(bytestream, offset);
    // Native asset
    if (asset_type == 0) {
        strlcpy(str_asset_row, _("XLM (native asset)"), sizeof(str_asset_row));
    }
    // 4-character custom
    if (asset_type == 1) {
        memcpy(str_asset_name, bytestream + *offset, 4);
        *offset += 4;

        strlcpy(str_asset_row, str_asset_name, sizeof(str_asset_row));
    }
    if (asset_type == 2) {
        memcpy(str_asset_name, bytestream + *offset, 12);
        *offset += 12;

        strlcpy(str_asset_row, str_asset_name, sizeof(str_asset_row));
    }
    // Issuer is read the same way for both types of custom assets
    if (asset_type == 1 || asset_type == 2) {
        stellar_xdr_read_address(issuer_bytes, bytestream, offset);
        stellar_publicAddressAsStr(issuer_bytes, str_asset_issuer, sizeof(str_asset_issuer));
        memcpy(str_asset_issuer_trunc, str_asset_issuer, 5);

        strlcat(str_asset_row, _(" ("), sizeof(str_asset_row));
        strlcat(str_asset_row, str_asset_issuer_trunc, sizeof(str_asset_row));
        strlcat(str_asset_row, _(")"), sizeof(str_asset_row));
    }

    char str_pay_amount[32];
    char str_amount[32];
    stellar_format_stroops(stellar_xdr_read_uint64(bytestream, offset), str_amount, sizeof(str_amount));

    strlcpy(str_pay_amount, _("Pay "), sizeof(str_pay_amount));
    strlcat(str_pay_amount, str_amount, sizeof(str_pay_amount));

    stellar_layoutTransactionDialog(
        str_pay_amount,
        str_asset_row,
        str_to,
        str_addr_rows[1],
        str_addr_rows[2]
    );
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        stellar_signingAbort();
        return;
    }

    // At this point, the operation is confirmed
    stellar_activeTx.confirmed_operations++;
}

void stellar_signingAbort()
{
    stellar_signing = false;
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
}

/*
 * returns the uint32_t at offset and increments offset by 4
 */
uint32_t stellar_xdr_read_uint32(uint8_t *bytestream, uint32_t *offset)
{
    uint32_t ret;
    memcpy(&ret, bytestream + *offset, 4);
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE32(ret, ret);
#endif

    *offset += 4;

    return ret;
}

/*
 * returns the uint64_t at offset and increments offset by 8
 */
uint64_t stellar_xdr_read_uint64(uint8_t *bytestream, uint32_t *offset)
{
    uint64_t ret;
    memcpy(&ret, bytestream + *offset, 8);
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE64(ret, ret);
#endif

    *offset += 8;

    return ret;
}

/*
 * returns a uint8_t representing a boolean value at offset and increments offset by 4
 */
uint8_t stellar_xdr_read_bool(uint8_t *bytestream, uint32_t *offset)
{
    uint8_t ret;
    uint32_t tmp_uint32;
    memcpy(&tmp_uint32, bytestream + *offset, 4);
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE32(tmp_uint32, tmp_uint32);
#endif
    *offset += 4;

    // Booleans are 4 bytes in XDR, but this returns true/false
    ret = (tmp_uint32) ? 1 : 0;

    return ret;
}

/*
 * Returns the 32 bytes that make up an address
 * Note that an address is actually 36 bytes where the first 4 indicate the key
 * type (which is always ED25519)
 */
void stellar_xdr_read_address(uint8_t *out_addr_bytes, uint8_t *bytestream, uint32_t *offset)
{
    // Read key type (always 0, so ignored)
    uint32_t key_type = stellar_xdr_read_uint32(bytestream, offset);
    if (key_type != 0) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Unsupported address type"));
        layoutHome();
        return;
    }

    // Read next 32 bytes
    memcpy(out_addr_bytes, bytestream + *offset, 32);
    *offset += 32;
}

/*
 * Copies the string in bytestream to out_str
 * XDR strings are:
 *  length (4 bytes)
 *  string (length bytes)
 */
void stellar_xdr_read_string(uint8_t *out_str, uint8_t *bytestream, uint32_t *offset)
{
    // First 4 bytes are string length
    uint32_t strlen = stellar_xdr_read_uint32(bytestream, offset);

    // Read next strlen bytes
    memcpy(out_str, bytestream + *offset, strlen);
    *offset += strlen;
}

uint32_t stellar_getXdrOffset()
{
    return stellar_activeTx.xdr_offset;
}

uint8_t stellar_allOperationsConfirmed()
{
    return stellar_activeTx.confirmed_operations == stellar_activeTx.num_operations;
}

StellarTransaction *stellar_getActiveTx()
{
    return &stellar_activeTx;
}

/*
 * Calculates and sets the signature for the active transaction
 */
void stellar_getSignatureForActiveTx(uint8_t *out_signature)
{
    HDNode *node = stellar_deriveNode(stellar_activeTx.account_index);

    // Signature is the ed25519 detached signature of the sha256 of all the bytes
    // that have been read so far
    uint8_t to_sign[32];
    sha256_Final(&(stellar_activeTx.sha256_ctx), to_sign);

    uint8_t signature[64];
    ed25519_sign(to_sign, sizeof(to_sign), node->private_key, node->public_key + 1, signature);

    memcpy(out_signature, signature, sizeof(signature));
}

/*
 * Returns number (representing stroops) formatted as XLM
 * For example, if number has value 1000000000 then it will be returned as "100.0"
 */
void stellar_format_stroops(uint64_t number, char *out, size_t outlen)
{
    bn_format_uint64(number, NULL, NULL, 7, 0, false, out, outlen);
}

/*
 * Returns a uint32 formatted as a string
 */
void stellar_format_uint32(uint64_t number, char *out, size_t outlen)
{
    bignum256 bn_number;
    bn_read_uint32(number, &bn_number);
    bn_format(&bn_number, NULL, NULL, 0, 0, false, out, outlen);
}

/*
 * Returns a uint64 formatted as a string
 */
void stellar_format_uint64(uint64_t number, char *out, size_t outlen)
{
    bignum256 bn_number;
    bn_read_uint64(number, &bn_number);
    bn_format(&bn_number, NULL, NULL, 0, 0, false, out, outlen);
}

/*
 * Breaks a 56 character address into 3 lines of lengths 16, 20, 20
 * This is to allow a small label to be prepended to the first line
 */
const char **stellar_lineBreakAddress(uint8_t *addrbytes)
{
    char str_fulladdr[56+1];
    static char rows[3][20+1];

    memset(rows, 0, sizeof(rows));

    // get full address string
    stellar_publicAddressAsStr(addrbytes, str_fulladdr, sizeof(str_fulladdr));

    // Break it into 3 lines
    strlcpy(rows[0], str_fulladdr + 0, 17);
    strlcpy(rows[1], str_fulladdr + 16, 21);
    strlcpy(rows[2], str_fulladdr + 16 + 20, 21);

    static const char *ret[3] = { rows[0], rows[1], rows[2] };
    return ret;
}

size_t stellar_publicAddressAsStr(uint8_t *bytes, char *out, size_t outlen)
{
    // version + key bytes + checksum
    uint8_t keylen = 1 + 32 + 2;
    uint8_t bytes_full[keylen];
    bytes_full[0] = 6 << 3; // 'G'

    memcpy(bytes_full + 1, bytes, 32);

    // Last two bytes are the checksum
    uint16_t checksum = stellar_crc16(bytes_full, 33);
    bytes_full[keylen-2] = checksum & 0x00ff;
    bytes_full[keylen-1] = (checksum>>8) & 0x00ff;

    base32_encode(bytes_full, keylen, out, outlen, BASE32_ALPHABET_RFC4648);

    // Public key will always be 56 characters
    return 56;
}

/*
 * CRC16 implementation compatible with the Stellar version
 * Ported from this implementation: http://introcs.cs.princeton.edu/java/61data/CRC16CCITT.java.html
 * Initial value changed to 0x0000 to match Stellar
 */
uint16_t stellar_crc16(uint8_t *bytes, uint32_t length)
{
    // Calculate checksum for existing bytes
    uint16_t crc = 0x0000;
    uint16_t polynomial = 0x1021;
    uint32_t i;
    uint8_t bit;
    uint8_t byte;
    uint8_t bitidx;
    uint8_t c15;

    for (i=0; i < length; i++) {
        byte = bytes[i];
        for (bitidx=0; bitidx < 8; bitidx++) {
            bit = ((byte >> (7 - bitidx) & 1) == 1);
            c15 = ((crc >> 15 & 1) == 1);
            crc <<= 1;
            if (c15 ^ bit) crc ^= polynomial;
        }
    }

    return crc & 0xffff;
}

/*
 * Writes 32-byte public key to out
 */
void stellar_getPubkeyAtIndex(uint32_t index, uint8_t *out, size_t outlen)
{
    if (outlen < 32) return;

    HDNode *node = stellar_deriveNode(index);

    memcpy(out, node->public_key + 1, outlen);
}

/*
 * Derives the HDNode at the given index
 * The prefix for this is m/44'/148'/index'
 */
HDNode *stellar_deriveNode(uint32_t index)
{
    static CONFIDENTIAL HDNode node;
    const char *curve = "ed25519";

    // Derivation path for Stellar is m/44'/148'/index'
    uint32_t address_n[3];
    address_n[0] = 0x80000000 | 44;
    address_n[1] = 0x80000000 | 148;
    address_n[2] = 0x80000000 | index;

    // Device not initialized, passphrase request cancelled, or unsupported curve
    if (!storage_getRootNode(&node, curve, true)) {
        return 0;
    }
    // Failed to derive private key
    if (hdnode_private_ckd_cached(&node, address_n, 3, NULL) == 0) {
        return 0;
    }

    hdnode_fill_public_key(&node);

    return &node;
}

/*
 * Reads stellar_activeTx and displays a summary of the overall transaction
 */
void stellar_layoutTransactionSummary()
{
    char str_lines[5][32];
    memset(str_lines, 0, sizeof(str_lines));

    char str_fee[12];
    char str_num_ops[12];

    // Will be set to true for some large hashes that don't fit on one screen
    uint8_t needs_memo_hash_confirm = 0;

    // Format the fee
    bignum256 bn_fee;
    bn_read_uint32(stellar_activeTx.fee, &bn_fee);
    bn_format(&bn_fee, NULL, _(" XLM"), 7, 0, false, str_fee, sizeof(str_fee));

    strlcpy(str_lines[0], _("Fee: "), sizeof(str_lines[0]));
    strlcat(str_lines[0], str_fee, sizeof(str_lines[0]));

    // add in numOperations
    bignum256 bn_num_ops;
    bn_read_uint32(stellar_activeTx.num_operations, &bn_num_ops);
    bn_format(&bn_num_ops, NULL, NULL, 0, 0, false, str_num_ops, sizeof(str_num_ops));

    strlcat(str_lines[0], _(" ("), sizeof(str_lines[0]));
    strlcat(str_lines[0], str_num_ops, sizeof(str_lines[0]));
    if (stellar_activeTx.num_operations == 1) {
        strlcat(str_lines[0], _(" op)"), sizeof(str_lines[0]));
    } else {
        strlcat(str_lines[0], _(" ops)"), sizeof(str_lines[0]));
    }

    // Display full address being used to sign transaction
    const char **str_addr_rows = stellar_lineBreakAddress(stellar_activeTx.account_id);

    stellar_layoutTransactionDialog(
        str_lines[0],
        _("Signing with:"),
        str_addr_rows[0],
        str_addr_rows[1],
        str_addr_rows[2]
    );
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        stellar_signingAbort();
        return;
    }

    // Reset lines for displaying memo
    memset(str_lines, 0, sizeof(str_lines));

    // Memo: none
    if (stellar_activeTx.memo_type == 0) {
        strlcpy(str_lines[0], _("[No Memo]"), sizeof(str_lines[0]));
    }
    // Memo: text
    if (stellar_activeTx.memo_type == 1) {
        strlcpy(str_lines[0], _("Memo (TEXT)"), sizeof(str_lines[0]));

        // Split 28-character string into two lines of 19 / 9
        strlcpy(str_lines[1], (const char*)stellar_activeTx.memo, 19 + 1);
        strlcpy(str_lines[2], (const char*)(stellar_activeTx.memo + 19), 9 + 1);
    }
    // Memo: ID
    if (stellar_activeTx.memo_type == 2) {
        strlcpy(str_lines[0], _("Memo (ID)"), sizeof(str_lines[0]));

        // Memo is a uint64
        uint32_t id_ptr = 0;
        uint64_t id_memo = stellar_xdr_read_uint64(stellar_activeTx.memo, &id_ptr);
        stellar_format_uint64(id_memo, str_lines[1], sizeof(str_lines[1]));
    }
    // Memo: hash
    if (stellar_activeTx.memo_type == 3) {
        needs_memo_hash_confirm = 1;
        strlcpy(str_lines[0], _("Memo (HASH)"), sizeof(str_lines[0]));
    }
    // Memo: return
    if (stellar_activeTx.memo_type == 4) {
        needs_memo_hash_confirm = 1;
        strlcpy(str_lines[0], _("Memo (RETURN)"), sizeof(str_lines[0]));
    }

    if (needs_memo_hash_confirm) {
        data2hex(stellar_activeTx.memo +  0, 8, str_lines[1]);
        data2hex(stellar_activeTx.memo +  8, 8, str_lines[2]);
        data2hex(stellar_activeTx.memo + 16, 8, str_lines[3]);
        data2hex(stellar_activeTx.memo + 24, 8, str_lines[4]);
    }

    stellar_layoutTransactionDialog(
        str_lines[0],
        str_lines[1],
        str_lines[2],
        str_lines[3],
        str_lines[4]
    );
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        stellar_signingAbort();
        return;
    }

    // Additional confirmation for some memo types
    /*
    if (needs_memo_hash_confirm) {
        char hash_str[4][17];

        data2hex(stellar_activeTx.memo +  0, 8, hash_str[0]);
        data2hex(stellar_activeTx.memo +  8, 8, hash_str[1]);
        data2hex(stellar_activeTx.memo + 16, 8, hash_str[2]);
        data2hex(stellar_activeTx.memo + 24, 8, hash_str[3]);

        stellar_layoutTransactionDialog(
            _("Confirm Memo Hash"),
            hash_str[0],
            hash_str[1],
            hash_str[2],
            hash_str[3]
        );
        if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
            stellar_signingAbort();
            return;
        }
    }
    */

    // Verify timebounds, if present
    memset(str_lines, 0, sizeof(str_lines));

    // Timebound: lower
    if (stellar_activeTx.timebound_min || stellar_activeTx.timebound_max) {
        time_t timebound;
        char str_timebound[32];
        const struct tm *tm;

        // stellar timestamp is 8 bytes, time_t is only 32 so check for overflow
        if (stellar_activeTx.timebound_min > INT32_MAX) {
            strlcpy(str_lines[1], _("ERR: value too large"), sizeof(str_lines[1]));
        }
        else {
            timebound = (time_t)stellar_activeTx.timebound_min;

            tm = gmtime(&timebound);
            strftime(str_timebound, sizeof(str_timebound), "%F %T (UTC)", tm);

            strlcpy(str_lines[0], _("Valid from:"), sizeof(str_lines[0]));
            if (stellar_activeTx.timebound_min) {
                strlcpy(str_lines[1], str_timebound, sizeof(str_lines[1]));
            }
            else {
                strlcpy(str_lines[1], _("[no restriction]"), sizeof(str_lines[1]));
            }
        }

        // Reset for timebound_max
        memset(str_timebound, 0, sizeof(str_timebound));

        // stellar timestamp is 8 bytes, time_t is only 32 so check for overflow
        if (stellar_activeTx.timebound_max > INT32_MAX) {
            strlcpy(str_lines[3], _("ERR: value too large"), sizeof(str_lines[3]));
        }
        else {
            timebound = (time_t)stellar_activeTx.timebound_max;

            tm = gmtime(&timebound);
            strftime(str_timebound, sizeof(str_timebound), "%F %T (UTC)", tm);

            strlcpy(str_lines[2], _("Valid until:"), sizeof(str_lines[2]));
            if (stellar_activeTx.timebound_min) {
                strlcpy(str_lines[3], str_timebound, sizeof(str_lines[3]));
            }
            else {
                strlcpy(str_lines[3], _("[no restriction]"), sizeof(str_lines[3]));
            }
        }
    }

    if (stellar_activeTx.timebound_min || stellar_activeTx.timebound_max) {
        stellar_layoutTransactionDialog(
            _("Confirm Time Bounds"),
            str_lines[0],
            str_lines[1],
            str_lines[2],
            str_lines[3]
        );
        if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
            stellar_signingAbort();
            return;
        }
    }
}

/*
 * Main dialog helper method. Allows displaying 5 lines.
 * A title showing the account being used to sign is always displayed.
 */
void stellar_layoutTransactionDialog(const char *line1, const char *line2, const char *line3, const char *line4, const char *line5)
{
    // Start with some initial padding and use these to track position as rendering moves down the screen
    int offset_x = 1;
    int offset_y = 1;
    int line_height = 9;

    char str_account_index[12];
    char str_pubaddr_truncated[6]; // G???? + null

    layoutLast = layoutDialogSwipe;
    layoutSwipe();
    oledClear();

    // Load up public address
    char str_pubaddr[56+1];
    memset(str_pubaddr, 0, sizeof(str_pubaddr));
    stellar_publicAddressAsStr(stellar_activeTx.account_id, str_pubaddr, sizeof(str_pubaddr));
    memcpy(str_pubaddr_truncated, str_pubaddr, 5);

    // Format account index
    stellar_format_uint32(stellar_activeTx.account_index + 1, str_account_index, sizeof(str_account_index));

    // Header
    // Ends up as: Signing with #1 (GABCD)
    char str_header[32];
    memset(str_header, 0, sizeof(str_header));
    strlcpy(str_header, _("Signing with #"), sizeof(str_header));
    strlcat(str_header, str_account_index, sizeof(str_header));
    strlcat(str_header, _(" ("), sizeof(str_header));
    strlcat(str_header, str_pubaddr_truncated, sizeof(str_header));
    strlcat(str_header, _(")"), sizeof(str_header));

    oledDrawString(offset_x, offset_y, str_header);
    offset_y += line_height;
    // Invert color on header
    oledInvert(0, 0, OLED_WIDTH, offset_y - 2);

    // Dialog contents begin
    if (line1) {
        oledDrawString(offset_x, offset_y, line1);
        offset_y += line_height;
    }
    if (line2) {
        oledDrawString(offset_x, offset_y, line2);
        offset_y += line_height;
    }
    if (line3) {
        oledDrawString(offset_x, offset_y, line3);
        offset_y += line_height;
    }
    if (line4) {
        oledDrawString(offset_x, offset_y, line4);
        offset_y += line_height;
    }
    if (line5) {
        oledDrawString(offset_x, offset_y, line5);
        offset_y += line_height;
    }

    // Cancel button
    oledDrawString(1, OLED_HEIGHT - 8, "\x15");
    oledDrawString(fontCharWidth('\x15') + 3, OLED_HEIGHT - 8, "Cancel");
    oledInvert(0, OLED_HEIGHT - 9, fontCharWidth('\x15') + oledStringWidth("Cancel") + 2, OLED_HEIGHT - 1);

    // Warnings (drawn centered between the buttons
    if (stellar_activeTx.network_type == 2) {
        // Warning: testnet
        oledDrawStringCenter(OLED_HEIGHT - 8, "WRN:TN");
    }
    if (stellar_activeTx.network_type == 3) {
        // Warning: private network
        oledDrawStringCenter(OLED_HEIGHT - 8, "WRN:PN");
    }


    // Next / confirm button
    oledDrawString(OLED_WIDTH - fontCharWidth('\x06') - 1, OLED_HEIGHT - 8, "\x06");
    oledDrawString(OLED_WIDTH - oledStringWidth("Next") - fontCharWidth('\x06') - 3, OLED_HEIGHT - 8, "Next");
    oledInvert(OLED_WIDTH - oledStringWidth("Next") - fontCharWidth('\x06') - 4, OLED_HEIGHT - 9, OLED_WIDTH - 1, OLED_HEIGHT - 1);

    oledRefresh();
}

void stellar_layoutStellarGetPublicKey(uint32_t index)
{
    char str_title[32];
    char str_index[12];

    stellar_format_uint32(index+1, str_index, sizeof(str_index));

    // Share account #100?
    strlcpy(str_title, _("Share account #"), sizeof(str_title));
    strlcat(str_title, str_index, sizeof(str_title));
    strlcat(str_title, _("?"), sizeof(str_title));

    // Derive node and calculate address
    uint8_t pubkey_bytes[32];
    stellar_getPubkeyAtIndex(index, pubkey_bytes, sizeof(pubkey_bytes));
    const char **str_addr_rows = stellar_lineBreakAddress(pubkey_bytes);

    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), _("Share public account ID?"),
        str_title,
        str_addr_rows[0],
        str_addr_rows[1],
        str_addr_rows[2],
        NULL, NULL
        );
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }
}