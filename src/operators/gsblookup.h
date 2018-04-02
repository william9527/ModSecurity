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

#ifndef SRC_OPERATORS_GSBLOOKUP_H_
#define SRC_OPERATORS_GSBLOOKUP_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"

namespace modsecurity {
namespace operators {

class GsbLookup : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a local lookup of Google's Safe Browsing using URLs in input
    against the GSB database previously configured using SecGsbLookupDb.
    When combined with capture operator it will save the matched url into
    tx.0 variable.
    \endverbatim


    Syntax

    \verbatim
    @gsbLookup REGEX
    \endverbatim


    Examples

    \verbatim
    The gsbLookup operator matches on success and is thus best used in
    combination with a block or redirect action. If you wish to block on
    successful lookups, the following example demonstrates how best to do
    it:

    Configure Google Safe Browsing database
    = SecGsbLookupDb /path/to/GsbMalware.dat

    Check response bodies for malicious links
    = SecRule RESPONSE_BODY "@gsbLookup =\"https?\:\/\/(.*?)\"" "phase:4,id:157,capture,log,block,msg:'Bad url detected in RESPONSE_BODY (Google Safe Browsing Check)',logdata:'http://www.google.com/safebrowsing/diagnostic?site=%{tx.0}'"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit GsbLookup(std::unique_ptr<RunTimeString> param)
        : Operator("GsbLookup", std::move(param)) { }

    bool evaluate(Transaction *transaction, const std::string &str);
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_GSBLOOKUP_H_
