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

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_REQBODY_PROCESSOR_H_
#define SRC_VARIABLES_REQBODY_PROCESSOR_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ReqbodyProcessor : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQBODY_PROCESSOR

    \verbatim
    Contains the name of the currently used request body processor. The
    possible values are URLENCODED, MULTIPART, and XML.

    = SecRule REQBODY_PROCESSOR "^XML$ chain,id:41"
    = SecRule XML "@validateDTD /opt/apache-frontend/conf/xml.dtd"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    ReqbodyProcessor()
        : Variable("REQBODY_PROCESSOR") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableReqbodyProcessor.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQBODY_PROCESSOR_H_
