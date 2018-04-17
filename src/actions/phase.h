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

#ifndef SRC_ACTIONS_PHASE_H_
#define SRC_ACTIONS_PHASE_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;
class Rule;

namespace actions {


class Phase : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Meta-data

    \verbatim
    Places the rule or chain into one of five available processing phases. It
    can also be used in SecDefaultAction to establish the rule defaults.

    There are aliases for some phase numbers:
        2 - request
        4 - response
        5 - logging

    Warning: Keep in mind that if you specify the incorrect phase, the
    variable used in the rule may not yet be available. This could lead to a
    false negative situation where your variable and operator may be correct,
    but it misses malicious data because you specified the wrong phase.
    \endverbatim


    Example

    \verbatim
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Phase(std::string action) : Action(action, ConfigurationKind),
        m_phase(0),
        m_secRulesPhase(0) { }

    bool init(std::string *error) override;
    bool evaluate(Rule *rule, Transaction *transaction) override;

    int m_phase;
    int m_secRulesPhase;
};

}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_PHASE_H_
