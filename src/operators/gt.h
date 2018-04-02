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

#ifndef SRC_OPERATORS_GT_H_
#define SRC_OPERATORS_GT_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"


namespace modsecurity {
namespace operators {

class Gt : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs numerical comparison and returns true if the input value is
    greater than the operator parameter. Macro expansion is performed on
    the parameter string before comparison.
    \endverbatim


    Syntax

    \verbatim
    @gt number
    \endverbatim


    Examples
    \verbatim
    Detect more than 15 headers in a request
    = SecRule &REQUEST_HEADERS_NAMES "@gt 15" "id:158"
    \endverbatim


    Details

    \verbatim
    \endverbatim


    Notes
    \verbatim
    - If a value is provided that cannot be converted to an
    integer (i.e a string) this operator will treat that value as 0.
    \endverbatim


    */
 public:
    explicit Gt(std::unique_ptr<RunTimeString> param)
        : Operator("Gt", std::move(param)) {
            m_couldContainsMacro = true;
        }
    bool evaluate(Transaction *transaction, const std::string &input) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_GT_H_
