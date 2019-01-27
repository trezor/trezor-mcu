#ifndef EOSIO_TOKEN_H
#define EOSIO_TOKEN_H

#include <stdbool.h>

typedef struct _EosActionCommon EosActionCommon;
typedef struct _EosActionTransfer EosActionTransfer;

/// \returns true iff successful.
bool eos_compileActionTransfer(const EosActionCommon *common,
                               const EosActionTransfer *action);

#endif
