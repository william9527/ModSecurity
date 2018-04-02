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

#ifndef SRC_OPERATORS_WITHIN_H_
#define SRC_OPERATORS_WITHIN_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"


namespace modsecurity {
namespace operators {

class Within : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Returns true if the input value (the needle) is found anywhere within
    the @within parameter (the haystack). Macro expansion is performed on
    the parameter string before comparison.
    \endverbatim


    Syntax

    \verbatim
    @within string separated by comma
    \endverbatim


    Examples

    \verbatim
    Detect request methods other than GET, POST and HEAD
    =SecRule REQUEST_METHOD "!@within GET,POST,HEAD"
    \endverbatim


    Details

    \verbatim
    \endverbatim


    Notes

    \verbatim
    - There are no delimiters for this operator, it is therefore often
      necessary to artificially impose some; this can be done using setvar.
      For instance in the example below, without the imposed delimiters
      (of '/') this rule would also match on the 'range' header (along with
      many other combinations), since 'range' is within the provided
      parameter. With the imposed delimiters, the rule would check for
      '/range/' when the range header is provided, and therefore would not
      match since '/range/ is not part of the @within parameter.
    \endverbatim

    */
 public:
    explicit Within(std::unique_ptr<RunTimeString> param)
        : Operator("Within", std::move(param)) {
            /** macro expansion: true */
            m_couldContainsMacro = true;
        }
    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &str, std::shared_ptr<RuleMessage> ruleMessage);
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_WITHIN_H_
