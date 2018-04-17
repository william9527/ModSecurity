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
#include "src/engine/lua.h"

#ifndef SRC_ACTIONS_EXEC_H_
#define SRC_ACTIONS_EXEC_H_

class Transaction;

namespace modsecurity {
class Transaction;
namespace actions {


class Exec : public Action {
    /** @ingroup ModSecurity_RefManual */
    /**

    Description

    Group: Non-disruptive

    \verbatim
    Executes an external script/binary supplied as parameter. If the parameter
    supplied to exec is a Lua script (detected by the .lua extension) the
    script will be processed internally. This means you will get direct access
    to the internal request context from the script. Please read the
    SecRuleScript documentation for more details on how to write Lua scripts.

    The exec action is executed independently from any disruptive actions
    specified. External scripts will always be called with no parameters. Some
    transaction information will be placed in environment variables. All the
    usual CGI environment variables will be there. You should be aware that
    forking a threaded process results in all threads being replicated in the
    new process. Forking can therefore incur larger overhead in a
    multithreaded deployment. The script you execute must write something
    (anything) to stdout; if it doesn’t, ModSecurity will assume that the
    script failed, and will record the failure.
    \endverbatim


    Example

    \verbatim
    # Run external program on rule match 
    = SecRule REQUEST_URI "^/cgi-bin/script\.pl" "phase:2,id:112,t:none,t:lowercase,t:normalizePath,block,\ exec:/usr/local/apache/bin/test.sh"

    # Run Lua script on rule match 
    = SecRule ARGS:p attack "phase:2,id:113,block,exec:/usr/local/apache/conf/exec.lua"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Exec(std::string action)
        : Action(action),
        m_script("") { }

    ~Exec() { }

    bool evaluate(Rule *rule, Transaction *transaction) override;
    bool init(std::string *error) override;

 private:
    std::string m_script;
    engine::Lua m_lua;
};


}  // namespace actions
}  // namespace modsecurity

#endif  // SRC_ACTIONS_EXEC_H_
