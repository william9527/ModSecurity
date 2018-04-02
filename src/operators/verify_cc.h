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

#ifndef SRC_OPERATORS_VERIFY_CC_H_
#define SRC_OPERATORS_VERIFY_CC_H_

#include <pcre.h>
#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"

namespace modsecurity {
namespace operators {

class VerifyCC : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Detects credit card numbers in input. This operator will first use the
    supplied regular expression to perform an initial match, following up
    with the Luhn algorithm calculation to minimize false positives.
    \endverbatim


    Syntax

    \verbatim
    @verifyCC regex
    \endverbatim


    Examples

    \verbatim
    Detect credit card numbers in parameters and prevent them from being logged to audit log
    = SecRule ARGS "@verifyCC \d{13,16}" "phase:2,id:194,nolog,pass,msg:'Potential credit card number',sanitiseMatched"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit VerifyCC(std::unique_ptr<RunTimeString> param)
        : Operator("VerifyCC", std::move(param)),
        m_pc(NULL),
        m_pce(NULL) { }
    ~VerifyCC();

    int luhnVerify(const char *ccnumber, int len);
    bool evaluate(Transaction *t, Rule *rule,
        const std::string& input,
        std::shared_ptr<RuleMessage> ruleMessage)  override;
    bool init(const std::string &param, std::string *error) override;
 private:
    pcre *m_pc;
    pcre_extra *m_pce;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_VERIFY_CC_H_
