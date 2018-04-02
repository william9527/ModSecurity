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

#ifndef SRC_OPERATORS_FUZZY_HASH_H_
#define SRC_OPERATORS_FUZZY_HASH_H_

#include <string>
#include <memory>
#include <utility>

#ifdef WITH_SSDEEP
#include <fuzzy.h>
#endif

#include "src/operators/operator.h"

namespace modsecurity {
namespace operators {


struct fuzzy_hash_chunk {
    char *data;
    struct fuzzy_hash_chunk *next;
};

class FuzzyHash : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    The fuzzyHash operator uses the ssdeep, which is a program for
    computing context triggered piecewise hashes (CTPH). Also called fuzzy
    hashes, CTPH can match inputs that have homologies. Such inputs have
    sequences of identical bytes in the same order, although bytes in
    between these sequences may be different in both content and length.
    \endverbatim


    Syntax

    \verbatim
    @fuzzyHash /path/to/ssdeep/hashes.txt threshold
    \endverbatim


    Examples

    \verbatim
    Detect SQL Injection inside request uri data"
    = SecRule REQUEST_BODY "@fuzzyHash /path/to/ssdeep/hashes.txt 6" "id:192372,log,deny"
    \endverbatim


    Details

    \verbatim
    For further information on ssdeep, visit its site:
    http://ssdeep.sourceforge.net/
    \endverbatim

    */
 public:
    explicit FuzzyHash(std::unique_ptr<RunTimeString> param)
        : Operator("FuzzyHash", std::move(param)),
        m_head(NULL),
        m_threshold(0) { }
    ~FuzzyHash();

    bool evaluate(Transaction *transaction, const std::string &std) override;

    bool init(const std::string &param, std::string *error) override;
 private:
    int m_threshold;
    struct fuzzy_hash_chunk *m_head;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_FUZZY_HASH_H_
