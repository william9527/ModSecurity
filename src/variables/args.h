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

#ifndef SRC_VARIABLES_ARGS_H_
#define SRC_VARIABLES_ARGS_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class Args_DictElement : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: ARGS

    \verbatim
    ARGS is a collection and can be used on its own (means all arguments
    including the POST Payload), with a static parameter (matches arguments
    with that name), or with a regular expression (matches all arguments with
    name that matches the regular expression). To look at only the query
    string or body arguments, see the ARGS_GET and ARGS_POST collections.

    Some variables are actually collections, which are expanded into more
    variables at runtime. The following example will examine all request
    arguments:

    = SecRule ARGS dirty "id:7"

    Sometimes, however, you will want to look only at parts of a collection.
    This can be achieved with the help of the selection operator(colon). The
    following example will only look at the arguments named p (do note that, in
    general, requests can contain multiple arguments with the same name):

    = SecRule ARGS:p dirty "id:8"

    It is also possible to specify exclusions. The following will examine all
    request arguments for the word dirty, except the ones named z (again, there
    can be zero or more arguments named z):

    = SecRule ARGS|!ARGS:z dirty "id:9"

    There is a special operator that allows you to count how many variables
    there are in a collection. The following rule will trigger if there is more
    than zero arguments in the request (ignore the second parameter for the
    time being):

    = SecRule &ARGS !^0$ "id:10"

    And sometimes you need to look at an array of parameters, each with a
    slightly different name. In this case you can specify a regular expression
    in the selection operator itself. The following rule will look into all
    arguments whose names begin with id_:

    = SecRule ARGS:/^id_/ dirty "id:11"

    Note : Using ARGS:p will not result in any invocations against the operator
    if argument p does not exist.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Args_DictElement(std::string dictElement)
        : Variable("ARGS" + std::string(":") + std::string(dictElement)),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableArgs.resolve(m_dictElement, l);
    }

    std::string m_dictElement;
};


class Args_NoDictElement : public Variable {
 public:
    Args_NoDictElement()
        : Variable("ARGS") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableArgs.resolve(l);
    }
};


class Args_DictElementRegexp : public Variable {
 public:
    explicit Args_DictElementRegexp(std::string dictElement)
        : Variable("ARGS:regex(" + dictElement + ")"),
        m_r(dictElement) {
    }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableArgs.resolveRegularExpression(&m_r, l);
    }

    Utils::Regex m_r;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_ARGS_H_

