/**
 * @file        tests/unit/rexglue/discord_shutdown_test.cpp
 * @brief       Process-exit regression test for the Discord RPC worker
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#include <rex/discord_rpc.h>

int main() {
  rex::discord_rpc::Start("discord-shutdown-regression-test");
  return 0;
}
