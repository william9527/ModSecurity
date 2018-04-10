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

#include <vector>
#include <string>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_ENV_H_
#define SRC_VARIABLES_ENV_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class Env : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: ENV

    \verbatim
    Collection that provides access to environment variables set by ModSecurity
    or other server modules. Requires a single parameter to specify the name of
    the desired variable.

    = # Set environment variable
    = SecRule REQUEST_FILENAME "printenv" "phase:2,id:15,pass,setenv:tag=suspicious"
    =
    = # Inspect environment variable
    = SecRule ENV:tag "suspicious" "id:16"
    =
    = # Reading an environment variable from other Apache module (mod_ssl)
    = SecRule TX:ANOMALY_SCORE "@gt 0" "phase:5,id:16,msg:'%{env.ssl_cipher}'"

    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Env(std::string _name)
        : Variable(_name) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_ENV_H_
