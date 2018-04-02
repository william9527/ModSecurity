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

#ifndef SRC_OPERATORS_VALIDATE_HASH_H_
#define SRC_OPERATORS_VALIDATE_HASH_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"


namespace modsecurity {
namespace operators {

class ValidateHash : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Validates REQUEST_URI that contains data protected by the hash engine.
    \endverbatim


    Syntax

    \verbatim
    @validatehash
    \endverbatim


    Examples

    \verbatim
    Validates requested URI that matches a regular expression.
    = SecRule REQUEST_URI "@validatehash" "product_info|product_list" "phase:1,deny,id:123456"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit ValidateHash(std::unique_ptr<RunTimeString> param)
        : Operator("ValidateHash", std::move(param)) { }
    bool evaluate(Transaction *transaction, const std::string  &str) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_VALIDATE_HASH_H_
