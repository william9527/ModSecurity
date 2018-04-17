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

#ifndef SRC_ACTIONS_DISRUPTIVE_ALLOW_H_
#define SRC_ACTIONS_DISRUPTIVE_ALLOW_H_

#ifdef __cplusplus
class Transaction;

namespace modsecurity {
class Transaction;
class Rule;

namespace actions {
namespace disruptive {


enum AllowType : int {
  /**
   *
   */
  NoneAllowType,
  /**
   *
   */
  RequestAllowType,
  /**
   *
   */
  PhaseAllowType,
  /**
   *
   */
  FromNowOnAllowType,
};


class Allow : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Disruptive

    \verbatim
    Stops rule processing on a successful match and allows the transaction to
    proceed.

    Starting with v2.5.0 allow was enhanced to allow for fine-grained control
    of what is done. The following rules now apply:

    If used one its own, like in the example above, allow will affect the
    entire transaction, stopping processing of the current phase but also
    skipping over all other phases apart from the logging phase. (The
    logging phase is special; it is designed to always execute.) If used with
    parameter "phase", allow will cause the engine to stop processing the
    current phase. Other phases will continue as normal.

    If used with parameter "request", allow will cause the engine to stop
    processing the current phase. The next phase to be processed will be
    phase RESPONSE_HEADERS.
    \endverbatim


    Example

    \verbatim
    # Do not process request but process response.
    = SecAction phase:1,allow:request,id:96

    # Do not process transaction (request and response).
    = SecAction phase:1,allow,id:97

    If you want to allow a response through, put a rule in phase RESPONSE_HEADERS and simply use allow on its own:

    # Allow response through.
    = SecAction phase:3,allow,id:98
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Allow(std::string action)
        : Action(action, RunTimeOnlyIfMatchKind),
        m_allowType(NoneAllowType) { }


    bool init(std::string *error) override;
    bool evaluate(Rule *rule, Transaction *transaction) override;
    bool isDisruptive() override { return true; }

    AllowType m_allowType;

    static std::string allowTypeToName(AllowType a) {
        if (a == NoneAllowType) {
            return "None";
        } else if (a == RequestAllowType) {
            return "Request";
        } else if (a == PhaseAllowType) {
            return "Phase";
        } else if (a == FromNowOnAllowType) {
            return "FromNowOn";
        } else {
            return "Unknown";
        }
    }
};


}  // namespace disruptive
}  // namespace actions
}  // namespace modsecurity
#endif

#endif  // SRC_ACTIONS_DISRUPTIVE_ALLOW_H_
