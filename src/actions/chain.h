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

#include "modsecurity/actions/action.h"

#ifndef SRC_ACTIONS_CHAIN_H_
#define SRC_ACTIONS_CHAIN_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;
class Rule;

namespace actions {


class Chain : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Flow

    \verbatim
    Chains the current rule with the rule that immediately follows it, creating
    a rule chain. Chained rules allow for more complex processing logic.
    
    Note: Rule chains allow you to simulate logical AND. The disruptive actions specified in the first portion of the chained rule will be triggered only if all of the variable checks return positive hits. If any one aspect of a chained rule comes back negative, then the entire rule chain will fail to match. Also note that disruptive actions, execution phases, metadata actions (id, rev, msg, tag, severity, logdata), skip, and skipAfter actions can be specified only by the chain starter rule.
    \endverbatim

    Example

    \verbatim
    # Refuse to accept POST requests that do not contain Content-Length header. 
    # (Do note that this rule should be preceded by a rule 
    # that verifies only valid request methods are used.) 
    = SecRule REQUEST_METHOD "^POST$" phase:1,chain,t:none,id:105
    =    SecRule &REQUEST_HEADERS:Content-Length "@eq 0" t:none
    \endverbatim

    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Chain(std::string action)
        : Action(action, ConfigurationKind) { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
};

}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_CHAIN_H_
