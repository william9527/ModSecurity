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

#ifndef SRC_OPERATORS_PM_FROM_FILE_H_
#define SRC_OPERATORS_PM_FROM_FILE_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/pm.h"


namespace modsecurity {
namespace operators {


class PmFromFile : public Pm {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a case-insensitive match of the provided phrases against the
    desired input value. The operator uses a set-based matching algorithm
    (Aho-Corasick), which means that it will match any number of keywords
    in parallel. When matching of a large number of keywords is needed,
    this operator performs much better than a regular expression.

    This operator is the same as @pm, except that it takes a list of files
    as arguments. It will match any one of the phrases listed in the file(s)
    anywhere in the target value.
    \endverbatim


    Syntax

    \verbatim
    @le integer
    \endverbatim


    Examples

    \verbatim
    Detect suspicious user agents using the keywords in the files
    /path/to/blacklist1 and blacklist2 (the latter must be placed in the
    same folder as the configuration file)
    = SecRule REQUEST_HEADERS:User-Agent "@pmFromFile /path/to/blacklist1 blacklist2" "id:167"
    \endverbatim


    Details

    \verbatim
    \endverbatim


    Notes

    \verbatim
    - Files must contain exactly one phrase per line. End of line markers
    (both LF and CRLF) will be stripped from each phrase and any
    whitespace trimmed from both the beginning and the end. Empty lines
    and comment lines (those beginning with the # character) will be
    ignored.
    - To allow easier inclusion of phrase files with rule sets, relative
    paths may be used to the phrase files. In this case, the path of the
    file containing the rule is prepended to the phrase file path.
    - The @pm operator phrases do not support metacharacters. Because this
    operator does not check for boundaries when matching, false positives
    are possible in some cases. For example, if you want to use @pm for IP
    address matching, the phrase 1.2.3.4 will potentially match more than
    one IP address (e.g., it will also match 1.2.3.40 or 1.2.3.41). To
    avoid the false positives, you can use your own boundaries in phrases.
    For example, use /1.2.3.4/ instead of just 1.2.3.4. Then, in your
    rules, also add the boundaries where appropriate. You will find a
    complete example in the example.
    \endverbatim


    */
 public:
    explicit PmFromFile(std::unique_ptr<RunTimeString> param)
        : Pm("PmFromFile", std::move(param)) { }
    explicit PmFromFile(std::string n, std::unique_ptr<RunTimeString> param)
        : Pm(n, std::move(param)) { }

    bool init(const std::string &file, std::string *error) override;
};


}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_PM_FROM_FILE_H_
