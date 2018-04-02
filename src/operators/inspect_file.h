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

#ifndef SRC_OPERATORS_INSPECT_FILE_H_
#define SRC_OPERATORS_INSPECT_FILE_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "src/engine/lua.h"


namespace modsecurity {
namespace operators {

class InspectFile : public Operator {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Executes an external program for every variable in the target list. The
    contents of the variable is provided to the script as the first
    parameter on the command line. The program must be specified as the
    first parameter to the operator. As of version 2.5.0, if the supplied
    program filename is not absolute, it is treated as relative to the
    directory in which the configuration file resides. Also as of version
    2.5.0, if the filename is determined to be a Lua script (based on its
    .lua extension), the script will be processed by the internal Lua
    engine. Internally processed scripts will often run faster (there is no
    process creation overhead) and have full access to the transaction
    context of ModSecurity.

    The @inspectFile operator was initially designed for file inspection
    (hence the name), but it can also be used in any situation that requires
    decision making using external logic.
    \endverbatim


    Syntax

    \verbatim
    @inspectFile /path/to/file.ext
    \endverbatim


    Examples

    \verbatim
    Execute external program to validate uploaded files
    = SecRule FILES_TMPNAMES "@inspectFile /path/to/util/runav.pl" "id:159"

    Example of using Lua script (placed in the same directory as the
    configuration file):
    = SecRule FILES_TMPNAMES "@inspectFile inspect.lua" "id:160"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit InspectFile(std::unique_ptr<RunTimeString> param)
        : Operator("InspectFile", std::move(param)),
        m_file(""),
        m_isScript(false) { }

    bool init(const std::string &param, std::string *error) override;
    bool evaluate(Transaction *transaction, const std::string &str) override;
 private:
    std::string m_file;
    bool m_isScript;
    engine::Lua m_lua;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_INSPECT_FILE_H_
