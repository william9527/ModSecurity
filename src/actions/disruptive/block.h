/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <string>
#include <memory>

#include "modsecurity/actions/action.h"
#include "modsecurity/rule_message.h"

#ifndef SRC_ACTIONS_DISRUPTIVE_BLOCK_H_
#define SRC_ACTIONS_DISRUPTIVE_BLOCK_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;

namespace actions {
namespace disruptive {


class Block : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Disruptive

    \verbatim
    Performs the disruptive action defined by the previous SecDefaultAction.

    This action is essentially a placeholder that is intended to be used by
    rule writers to request a blocking action, but without specifying how the
    blocking is to be done. The idea is that such decisions are best left to
    rule users, as well as to allow users, to override blocking if they so
    desire. In future versions of ModSecurity, more control and functionality
    will be added to define "how" to block.


    \endverbatim


    Example

    \verbatim
    # Specify how blocking is to be done 
    = SecDefaultAction phase:2,deny,id:101,status:403,log,auditlog

    # Detect attacks where we want to block 
    = SecRule ARGS attack1 phase:2,block,id:102

    # Detect attacks where we want only to warn 
    = SecRule ARGS attack2 phase:2,pass,id:103

    It is possible to use the SecRuleUpdateActionById directive to override
    how a rule handles blocking. This is useful in three cases:

    1. If a rule has blocking hard-coded, and you want it to use the policy you
    determine
    2. If a rule was written to block, but you want it to only warn
    3. If a rule was written to only warn, but you want it to block
    The following example demonstrates the first case, in which the hard-coded
    block is removed in favor of the user-controllable block:

    # Specify how blocking is to be done 
    = SecDefaultAction phase:2,deny,status:403,log,auditlog,id:104

    # Detect attacks and block 
    = SecRule ARGS attack1 phase:2,id:1,deny

    # Change how rule ID 1 blocks 
    = SecRuleUpdateActionById 1 block
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Block(std::string action) : Action(action) { }

    bool evaluate(Rule *rule, Transaction *transaction,
        std::shared_ptr<RuleMessage> rm) override;
    bool isDisruptive() override { return true; }
};


}  // namespace disruptive
}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_DISRUPTIVE_BLOCK_H_
