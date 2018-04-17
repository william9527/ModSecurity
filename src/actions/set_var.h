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
#include "src/run_time_string.h"

#ifndef SRC_ACTIONS_SET_VAR_H_
#define SRC_ACTIONS_SET_VAR_H_

namespace modsecurity {
class Transaction;
class Rule;

namespace actions {

enum SetVarOperation {
    /* Set variable to something */
    setOperation,
    /* read variable, sum predicate and set */
    sumAndSetOperation,
    /* read variable, substract predicate and set */
    substractAndSetOperation,
    /* set variable to 1 */
    setToOneOperation,
    /* unset operation */
    unsetOperation,
};

class SetVar : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    Creates, removes, or updates a variable. Variable names are
    case-insensitive.
    \endverbatim


    Example

    \verbatim
    To create a variable and set its value to 1 (usually used for setting flags), use: setvar:TX.score

    To create a variable and initialize it at the same time, use: setvar:TX.score=10

    To remove a variable, prefix the name with an exclamation mark: setvar:!TX.score

    To increase or decrease variable value, use + and - characters in front of a numerical value: setvar:TX.score=+5

    Example from OWASP CRS:
    = SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bsys\.user_catalog\b" \
		"phase:2,rev:'2.1.3',capture,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:replaceComments,t:compressWhiteSpace,ctl:auditLogParts=+E, \
block,msg:'Blind SQL Injection Attack',id:'959517',tag:'WEB_ATTACK/SQL_INJECTION',tag:'WASCTC/WASC-19',tag:'OWASP_TOP_10/A1',tag:'OWASP_AppSensor/CIE1', \
tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, \
setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}=%{tx.0}"

    Note: When used in a chain this action will be executed when an individual
    rule matches and not the entire chain.This means that

    = SecRule REQUEST_FILENAME "@contains /test.php" "chain,id:7,phase:1,t:none,nolog,setvar:tx.auth_attempt=+1" 
    = SecRule ARGS_POST:action "@streq login" "t:none"

    will increment every time that test.php is visited (regardless of the
    parameters submitted). If the desired goal is to set the variable only if
    the entire rule matches, it should be included in the last rule of the
    chain. For instance:

    = SecRule REQUEST_FILENAME "@streq test.php" "chain,id:7,phase:1,t:none,nolog"
    = SecRule ARGS_POST:action "@streq login" "t:none,setvar:tx.auth_attempt=+1"

    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    SetVar(SetVarOperation operation,
        std::unique_ptr<modsecurity::Variables::Variable> variable,
        std::unique_ptr<RunTimeString> predicate)
        : Action("setvar"),
        m_operation(operation),
        m_variable(std::move(variable)),
        m_string(std::move(predicate)) { }

    SetVar(SetVarOperation operation,
        std::unique_ptr<modsecurity::Variables::Variable> variable)
        : Action("setvar"),
        m_operation(operation),
        m_variable(std::move(variable)) { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
    bool init(std::string *error) override;

 private:
    SetVarOperation m_operation;
    std::unique_ptr<modsecurity::Variables::Variable> m_variable;
    std::unique_ptr<RunTimeString> m_string;
};

}  // namespace actions
}  // namespace modsecurity


#endif  // SRC_ACTIONS_SET_VAR_H_
