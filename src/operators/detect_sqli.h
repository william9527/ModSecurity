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

#ifndef SRC_OPERATORS_DETECT_SQLI_H_
#define SRC_OPERATORS_DETECT_SQLI_H_

#include <string>
#include <list>

#include "src/operators/operator.h"

namespace modsecurity {
namespace operators {

class DetectSQLi : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Returns true if SQL injection payload is found. This operator uses
    LibInjection to detect SQLi attacks.
    \endverbatim


    Syntax

    \verbatim
    @detectSQLi string
    \endverbatim


    Examples

    \verbatim
    Detect SQL Injection inside request uri data"
    = SecRule REQUEST_URI "@detectSQLi" "id:152"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    DetectSQLi()
        : Operator("DetectSQLi") {
            m_match_message.assign("detected SQLi using libinjection.");
        }

    bool evaluate(Transaction *t, Rule *rule,
        const std::string& input,
        std::shared_ptr<RuleMessage> ruleMessage) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_DETECT_SQLI_H_
