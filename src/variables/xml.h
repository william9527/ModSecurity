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

#ifndef SRC_VARIABLES_XML_H_
#define SRC_VARIABLES_XML_H_

#include "src/variables/variable.h"
#include "src/variables/xml.h"

namespace modsecurity {

class Transaction;
namespace Variables {


/* Invocation without an XPath expression makes sense
 * with functions that manipulate the document tree.
 */
class XML_NoDictElement : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: XML

    \verbatim
    Special collection used to interact with the XML parser. It can be used
    standalone as a target for the validateDTD and validateSchema operator.
    Otherwise, it must contain a valid XPath expression, which will then be
    evaluated against a previously parsed XML DOM tree.

    = SecDefaultAction log,deny,status:403,phase:2,id:90
    = SecRule REQUEST_HEADERS:Content-Type ^text/xml$ "phase:1,id:87,t:lowercase,nolog,pass,ctl:requestBodyProcessor=XML"
    = SecRule REQBODY_PROCESSOR "!^XML$" skipAfter:12345,id:88
    = SecRule XML:/employees/employee/name/text() Fred "id:89"
    = SecRule XML:/xq:employees/employee/name/text() Fred "id:12345,xmlns:xq=http://www.example.com/employees"

    The first XPath expression does not use namespaces. It would match against
    payload such as this one:

    = <employees>
    =     <employee>
    =         <name>Fred Jones</name>
    =         <address location="home">
    =             <street>900 Aurora Ave.</street>
    =             <city>Seattle</city>
    =             <state>WA</state>
    =             <zip>98115</zip>
    =         </address>
    =         <address location="work">
    =             <street>2011 152nd Avenue NE</street>
    =             <city>Redmond</city>
    =             <state>WA</state>
    =             <zip>98052</zip>
    =         </address>
    =         <phone location="work">(425)555-5665</phone>
    =         <phone location="home">(206)555-5555</phone>
    =         <phone location="mobile">(206)555-4321</phone>
    =     </employee>
    = </employees>
    = The second XPath expression does use namespaces. It would match the following payload:

    = <xq:employees xmlns:xq="http://www.example.com/employees">
    =     <employee>
    =         <name>Fred Jones</name>
    =         <address location="home">
    =             <street>900 Aurora Ave.</street>
    =             <city>Seattle</city>
    =             <state>WA</state>
    =             <zip>98115</zip>
    =         </address>
    =         <address location="work">
    =             <street>2011 152nd Avenue NE</street>
    =             <city>Redmond</city>
    =             <state>WA</state>
    =             <zip>98052</zip>
    =         </address>
    =         <phone location="work">(425)555-5665</phone>
    =         <phone location="home">(206)555-5555</phone>
    =         <phone location="mobile">(206)555-4321</phone>
    =     </employee>
    = </xq:employees>
    Note the different namespace used in the second example.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    XML_NoDictElement()
        : Variable("XML"),
        m_plain("[XML document tree]"),
        m_var(&m_name, &m_plain) {
        }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        l->push_back(new VariableValue(&m_var));
    }

    std::string m_plain;
    VariableValue m_var;
};


class XML : public Variable {
 public:
    explicit XML(std::string _name)
        : Variable(_name) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_XML_H_
