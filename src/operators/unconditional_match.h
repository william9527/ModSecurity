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

#ifndef SRC_OPERATORS_UNCONDITIONAL_MATCH_H_
#define SRC_OPERATORS_UNCONDITIONAL_MATCH_H_

#include <string>
#include <list>

#include "modsecurity/transaction.h"
#include "src/operators/operator.h"

namespace modsecurity {
namespace operators {

class UnconditionalMatch : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Will force the rule to always return true. This is similar to SecAction
    however all actions that occur as a result of a rule matching will fire
    such as the setting of MATCHED_VAR. This can also be part a chained
    rule.
    \endverbatim


    Syntax

    \verbatim
    @le integer
    \endverbatim


    Examples

    \verbatim
    = SecRule REMOTE_ADDR "@unconditionalMatch" "id:1000,phase:1,pass,nolog,t:hexEncode,setvar:TX.ip_hash=%{MATCHED_VAR}"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    UnconditionalMatch()
        : Operator("UnconditionalMatch") { }

    bool evaluate(Transaction *transaction, const std::string &exp) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_UNCONDITIONAL_MATCH_H_
