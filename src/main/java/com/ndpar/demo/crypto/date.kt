package com.ndpar.demo.crypto

import java.time.Duration
import java.time.Period
import java.time.temporal.TemporalAmount
import java.util.*

val Int.days: Period
    get() = Period.ofDays(this)

val Long.seconds: Duration
    get() = Duration.ofSeconds(this)

operator fun Date.minus(duration: TemporalAmount): Date =
    Date.from(this.toInstant().minus(duration))

operator fun Date.plus(duration: TemporalAmount): Date =
    Date.from(this.toInstant().plus(duration))