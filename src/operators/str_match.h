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

#ifndef SRC_OPERATORS_STR_MATCH_H_
#define SRC_OPERATORS_STR_MATCH_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"


namespace modsecurity {
namespace operators {

class StrMatch : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a string match of the provided word against the desired
    input value. The operator uses the pattern matching Boyer-Moore-Horspool
    algorithm, which means that it is a single pattern matching operator.
    This operator performs much better than a regular expression.
    \endverbatim


    Syntax

    \verbatim
    @le integer
    \endverbatim


    Examples

    \verbatim
    Detect suspicious client by looking at the user agent identification
    = SecRule REQUEST_HEADERS:User-Agent "@strmatch WebZIP" "id:177"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit StrMatch(std::unique_ptr<RunTimeString> param)
        : Operator("StrMatch", std::move(param)) {
            m_couldContainsMacro = true;
        }

    bool evaluate(Transaction *transaction, const std::string &input) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_STR_MATCH_H_
