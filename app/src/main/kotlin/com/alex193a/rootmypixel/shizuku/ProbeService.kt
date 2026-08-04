package com.alex193a.rootmypixel.shizuku

/**
 * Probe-only twin of [ExploitService], so unbinding a probe (which destroys the
 * user service process) can never kill a running exploit or its root daemon.
 */
class ProbeService : ExploitService()
