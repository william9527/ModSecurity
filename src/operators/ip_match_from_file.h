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
#ifndef SRC_OPERATORS_IP_MATCH_FROM_FILE_H_
#define SRC_OPERATORS_IP_MATCH_FROM_FILE_H_

#include <string>
#include <memory>
#include <utility>

#include "src/operators/ip_match.h"

namespace modsecurity {
namespace operators {

class IpMatchFromFile : public IpMatch {
    /** @ingroup ModSecurity_Operator ModSecurity_RefManual ModSecurity_RefManualOp */
    /**

    Description

    \verbatim
    Performs a fast ipv4 or ipv6 match of REMOTE_ADDR variable, loading
    data from a file. Can handle the following formats:

    - Full IPv4 Address - 192.168.1.100
    - Network Block/CIDR Address - 192.168.1.0/24
    - Full IPv6 Address - 2001:db8:85a3:8d3:1319:8a2e:370:7348
    - Network Block/CIDR Address - 2001:db8:85a3:8d3:1319:8a2e:370:0/24
    \endverbatim


    Syntax

    \verbatim
    @ipMatchFromFile /path/to/file.txt
    \endverbatim


    Examples

    \verbatim
    = SecRule REMOTE_ADDR "@ipMatchFromFile ips.txt" "id:163"
    \endverbatim


    Details

    \verbatim
    \endverbatim


    Notes

    \verbatim
    - As of v2.9.0-RC1 this operator also supports to load content served
    by an HTTPS server.
    - When used with content served by a HTTPS server, the directive
    SecRemoteRulesFailAction can be used to configure a warning instead of
    an abort, when the remote content could not be retrieved.
    \endverbatim

    */
 public:
    explicit IpMatchFromFile(std::unique_ptr<RunTimeString> param)
        : IpMatch("IpMatchFromFile", std::move(param)) { }
    IpMatchFromFile(std::string n, std::unique_ptr<RunTimeString> param)
        : IpMatch(n, std::move(param)) { }
    bool init(const std::string& file, std::string *error) override;
};

}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_IP_MATCH_FROM_FILE_H_
