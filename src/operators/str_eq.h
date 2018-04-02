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
#include <utility>

#include "modsecurity/transaction.h"
#include "src/operators/operator.h"


#ifndef SRC_OPERATORS_STR_EQ_H_
#define SRC_OPERATORS_STR_EQ_H_


namespace modsecurity {
namespace operators {

class StrEq : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a string comparison and returns true if the parameter string is
    identical to the input string. Macro expansion is performed on the
    parameter string before comparison.
    \endverbatim


    Syntax

    \verbatim
    @streq string
    \endverbatim


    Examples

    \verbatim
    Detect request parameters "foo" that do not # contain "bar", exactly.
    = SecRule ARGS:foo "!@streq bar" "id:176"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit StrEq(std::unique_ptr<RunTimeString> param)
        : Operator("StrEq", std::move(param)) { }

    bool evaluate(Transaction *transaction, const std::string &str) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_STR_EQ_H_
