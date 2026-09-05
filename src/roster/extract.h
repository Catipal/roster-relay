// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_EXTRACT_H
#define BITCOIN_ROSTER_EXTRACT_H

#include <vector>

class CScript;

namespace roster {

/**
 * Pull a record payload out of an OP_RETURN output.
 *
 * Kept apart from record.{h,cpp} so that the parser stays a pure function over
 * bytes with no script dependency, and shared rather than duplicated because
 * the index and the block filter must agree exactly on which outputs carry a
 * record. Two copies of this rule would eventually disagree, and a filter that
 * disagrees with the index is a filter that silently misses blocks.
 *
 * Requires exactly one data push and nothing following it, so a record has one
 * canonical script encoding rather than several.
 */
bool ExtractOpReturnPayload(const CScript& script, std::vector<unsigned char>& out);

} // namespace roster

#endif // BITCOIN_ROSTER_EXTRACT_H
