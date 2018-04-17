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
#include "src/actions/transformations/transformation.h"

#ifndef SRC_ACTIONS_TRANSFORMATIONS_MD5_H_
#define SRC_ACTIONS_TRANSFORMATIONS_MD5_H_

#ifdef __cplusplus
namespace modsecurity {
class Transaction;

namespace actions {
namespace transformations {

class Md5 : public Transformation {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Transformation

    \verbatim
    Calculates an MD5 hash from the data in input. The computed hash is in a
    raw binary form and may need encoded into text to be printed (or logged).
    Hash functions are commonly used in combination with hexEncode (for
    example: t:md5,t:hexEncode).
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Md5(std::string action) : Transformation(action) { }

    std::string evaluate(std::string exp,
        Transaction *transaction) override;
};

}  // namespace transformations
}  // namespace actions
}  // namespace modsecurity

#endif

#endif  // SRC_ACTIONS_TRANSFORMATIONS_MD5_H_
