#ifndef EOSIO_SYSTEM_H
#define EOSIO_SYSTEM_H

#include <stdbool.h>

typedef struct _EosActionBuyRam EosActionBuyRam;
typedef struct _EosActionBuyRamBytes EosActionBuyRamBytes;
typedef struct _EosActionCommon EosActionCommon;
typedef struct _EosActionDelegate EosActionDelegate;
typedef struct _EosActionDeleteAuth EosActionDeleteAuth;
typedef struct _EosActionLinkAuth EosActionLinkAuth;
typedef struct _EosActionNewAccount EosActionNewAccount;
typedef struct _EosActionRefund EosActionRefund;
typedef struct _EosActionSellRam EosActionSellRam;
typedef struct _EosActionUndelegate EosActionUndelegate;
typedef struct _EosActionUnlinkAuth EosActionUnlinkAuth;
typedef struct _EosActionUpdateAuth EosActionUpdateAuth;
typedef struct _EosActionVoteProducer EosActionVoteProducer;
typedef struct _EosAuthorization EosAuthorization;

/// \returns true iff successful.
bool eos_compileActionDelegate(const EosActionCommon *common,
                               const EosActionDelegate *action);

/// \returns true iff successful.
bool eos_compileActionUndelegate(const EosActionCommon *common,
                                 const EosActionUndelegate *action);

/// \returns true iff successful.
bool eos_compileActionRefund(const EosActionCommon *common,
                             const EosActionRefund *action);

/// \returns true iff successful.
bool eos_compileActionBuyRam(const EosActionCommon *common,
                             const EosActionBuyRam *action);

/// \returns true iff successful.
bool eos_compileActionBuyRamBytes(const EosActionCommon *common,
                                  const EosActionBuyRamBytes *action);

/// \returns true iff successful.
bool eos_compileActionSellRam(const EosActionCommon *common,
                              const EosActionSellRam *action);

/// \returns true iff successful.
bool eos_compileActionVoteProducer(const EosActionCommon *common,
                                   const EosActionVoteProducer *action);

/// \returns true iff successful.
bool eos_compileAuthorization(const char *title, const EosAuthorization *auth);

/// \returns true iff successful.
bool eos_compileActionUpdateAuth(const EosActionCommon *common,
                                 const EosActionUpdateAuth *action);

/// \returns true iff successful.
bool eos_compileActionDeleteAuth(const EosActionCommon *common,
                                 const EosActionDeleteAuth *action);

/// \returns true iff successful.
bool eos_compileActionLinkAuth(const EosActionCommon *common,
                               const EosActionLinkAuth *action);

/// \returns true iff successful.
bool eos_compileActionUnlinkAuth(const EosActionCommon *common,
                                 const EosActionUnlinkAuth *action);

/// \returns true iff successful.
bool eos_compileActionNewAccount(const EosActionCommon *common,
                                 const EosActionNewAccount *action);

#endif
